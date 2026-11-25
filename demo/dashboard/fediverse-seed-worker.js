/// Fediverse Dashboard: registration worker
///
/// Runs in a Web Worker, beside the page, so the page keeps showing the zone
/// while it registers. It loads its own copy of the sig0lease WASM, and is
/// the one place that registers: every registration goes through its queue,
/// one at most each SEED_INTERVAL, in this order:
///   1. what the visitor asks for: add, edit or remove an entry
///   2. renewals: each entry this browser keeps (has the key for) is
///      registered again when 80 to 85% of its LEASE has passed
///   3. seeding: each instance of INSTANCES_MD that the zone does not have
///      yet (when the page asks for it)
///
/// An entry is an SRP host named after the domain of its URL
/// (`chaos.social` -> `chaos-social`), with the domain's addresses, and one
/// `_fedi._tcp` instance of the same label, on port 443, in the subtypes of
/// its projects. The SRV record names the host in the zone, so the TXT key
/// `url` keeps the entry's own URL, which the dashboard links to. Leases of
/// the records and of the KEY are both LEASE, so a name is free again when
/// its entry is not renewed.
///
/// An instance is registered already when the dashboard shows it (the page
/// sends the names it shows after every refresh), or when its SRV record
/// answers, asked right before registering it. When the rate limit in front
/// of the proxy refuses a request, the worker waits SEED_RETRY_MIN, doubled
/// on each refusal up to SEED_RETRY_MAX, and tries the request again.
///
/// Entries are kept by the page in localStorage (the worker has none), by
/// `entry_key(host, zone)`: `{host, key, url, subtypes, registered}`.
///
/// Messages from the page:
///   {type: 'registered', names}   the instance names the dashboard shows
///   {type: 'start', zone, doh, registrar, entries, seed}
///                                 work in `zone`, asking `doh`, at the SRP
///                                 registrar `registrar`; `entries` are the
///                                 kept entries by their storage key; `seed`
///                                 registers the instances of INSTANCES_MD
///   {type: 'add', id, url, subtypes}       register a new entry
///   {type: 'edit', id, host, url, subtypes}  change an entry this browser
///                                 keeps; another domain moves it to another
///                                 host
///   {type: 'remove', id, host}    withdraw an entry this browser keeps
/// Messages to the page:
///   {type: 'status', state, text, title}
///   {type: 'entry', storage_key, entry}   keep this entry
///   {type: 'forget', storage_key}         the entry is gone or not ours
///   {type: 'registered', name, subtypes}  an instance this worker registered
///   {type: 'done', id, error}             the visitor's request is done;
///                                         `error` is null or a message

importScripts('wasm_exec.js', 'services.js', 'fediverse.js');

/// job priorities, lowest first
const VISITOR = 0;
const RENEWAL = 1;
const SEEDING = 2;

/// folded names of the instances the dashboard shows
let shown = new Set();
let config = null;
/// storage key -> entry {host, key, url, subtypes, registered, due, queued}
const entries = new Map();
/// jobs {priority, order, run}
const queue = [];
let order = 0;
/// when the last registration was answered, in ms since the epoch
let last_registration = 0;
/// what the status line says besides the progress, e.g. a rate limit wait
let waiting = '';
/// seeding progress, while it runs
const seeding = {
  total: 0,
  done: 0,
  existing: 0,
  registered: 0,
  held: 0,
  failed: [],
  running: false,
};

self.onmessage = (event) => {
  const message = event.data;
  switch (message.type) {
    case 'registered':
      shown = new Set(message.names.map(fold));
      break;
    case 'start':
      if (!config) {
        config = message;
        start(message).catch((error) => {
          console.error('the registration worker failed', error);
          status('error', 'Registering failed: ' + error.message);
        });
      }
      break;
    case 'add':
    case 'edit':
    case 'remove':
      enqueue(VISITOR, () => visitor_request(message));
      break;
  }
};

function status(state, text, title) {
  postMessage({type: 'status', state: state, text: text, title: title || ''});
}

/// put the status line together from the seeding progress, the entries
/// kept and `waiting`
function report() {
  const kept = [...entries.values()].filter(e => e.url && e.registered);
  const parts = [];
  if (seeding.running) {
    parts.push('Registering listed instances ' + seeding.done + '/' +
               seeding.total + ' · ' + seeding.existing +
               ' registered already · ' + seeding.registered + ' new' +
               (seeding.held ? ' · ' + seeding.held + ' held by others' : ''));
  }
  if (kept.length || !seeding.running) {
    const next = Math.min(...kept.map(e => e.due));
    parts.push('Keeping ' + kept.length +
               (kept.length === 1 ? ' entry' : ' entries') + ' registered' +
               (kept.length && isFinite(next) ?
                    ', next renewal in ' +
                        Math.max(0, Math.round((next - Date.now()) / 1000)) +
                        ' s' :
                    ''));
  }
  if (seeding.failed.length) {
    parts.push(seeding.failed.length + ' failed');
  }
  if (waiting) {
    parts.push(waiting);
  }
  const state = waiting ? 'waiting' :
      seeding.failed.length ? 'error' :
      seeding.running        ? 'loading' :
                               'ok';
  status(state, parts.join(' · '), seeding.failed.join('\n'));
}

/// load the sig0lease WASM, which sets the global `sig0lease` (see sig0.js)
async function load_wasm() {
  const go = new Go();
  const response = await fetch('sig0lease-web.wasm.gz');
  if (!response.ok) {
    throw new Error('sig0lease-web.wasm.gz: ' + response.status + ' ' +
                    response.statusText);
  }
  const wasm = await new Response(response.body.pipeThrough(
      new DecompressionStream('gzip'))).arrayBuffer();
  const {instance} = await WebAssembly.instantiate(wasm, go.importObject);
  go.run(instance);
}

/// run `f`; while the rate limit refuses it, wait and run it again
async function patiently(what, f) {
  let wait = SEED_RETRY_MIN;
  for (;;) {
    try {
      return await f();
    } catch (error) {
      if (!rate_limited(error)) {
        throw error;
      }
      console.warn(what + ': rate limited, waiting ' + wait / 1000 + ' s',
                   error);
      for (let left = wait / 1000; left > 0; left--) {
        waiting = 'rate limited, continuing in ' + left + ' s';
        report();
        await sleep(1000);
      }
      waiting = '';
      wait = Math.min(wait * 2, SEED_RETRY_MAX);
    }
  }
}

function enqueue(priority, run) {
  queue.push({priority: priority, order: order++, run: run});
}

/// load the WASM, take the kept entries, queue the seeding and work the
/// queue until the page closes
async function start({entries: kept, seed}) {
  status('loading', 'Loading the registration worker …');
  await load_wasm();
  const now = Date.now();
  for (const [storage_key, entry] of Object.entries(kept)) {
    entries.set(storage_key, {
      ...entry,
      // a kept entry is renewed at 80 to 85% of its lease, at once when
      // that is past or unknown; one without URL is only a key
      due: !entry.url ? Infinity :
          entry.registered ? renewal_time(entry.registered) :
                             now,
      queued: false,
    });
  }
  if (seed) {
    const response = await fetch(INSTANCES_MD);
    if (!response.ok) {
      throw new Error(INSTANCES_MD + ': ' + response.status + ' ' +
                      response.statusText);
    }
    const listed = parse_instances(await response.text());
    seeding.total = listed.length;
    seeding.running = listed.length > 0;
    for (const instance of listed) {
      enqueue(SEEDING, () => seed_instance(instance));
    }
  }
  await work();
}

/// when to renew an entry registered at `registered`: after 80 to 85% of
/// LEASE, at random, so that entries registered together spread out
function renewal_time(registered) {
  return registered + LEASE * 1000 * (0.8 + 0.05 * Math.random());
}

/// run the jobs, the most urgent first; queue the renewals that are due
async function work() {
  for (;;) {
    const now = Date.now();
    for (const entry of entries.values()) {
      if (entry.url && !entry.queued && entry.due <= now) {
        entry.queued = true;
        enqueue(RENEWAL, () => renew(entry));
      }
    }
    if (queue.length === 0) {
      report();
      await sleep(1000);
      continue;
    }
    queue.sort((a, b) => a.priority - b.priority || a.order - b.order);
    const job = queue.shift();
    try {
      await job.run();
    } catch (error) {
      console.error('a registration job failed', error);
    }
    report();
  }
}

/// the storage key of the entry at host label `host`
function storage_key_of(host) {
  return entry_key(host, config.zone);
}

/// the instance name of host label `host`
function instance_name(host) {
  return host + '.' + FEDI_TYPE + '.' + config.zone;
}

/// keep `entry` (in this worker and in the page)
function keep(entry) {
  const storage_key = storage_key_of(entry.host);
  entries.set(storage_key, entry);
  postMessage({
    type: 'entry',
    storage_key: storage_key,
    entry: {
      host: entry.host,
      key: entry.key,
      url: entry.url,
      subtypes: entry.subtypes,
      registered: entry.registered,
    },
  });
}

/// forget the entry at host label `host`
function forget(host) {
  const storage_key = storage_key_of(host);
  entries.delete(storage_key);
  postMessage({type: 'forget', storage_key: storage_key});
}

/// whether the zone has an instance at host label `host`: the dashboard
/// shows it, or its SRV record answers
async function present(host) {
  const name = instance_name(host);
  if (shown.has(fold(name))) {
    return true;
  }
  const srv = await patiently(
      host, () => sig0lease.lookup(config.doh, name, 'SRV'));
  return srv.records.some(r => r.type === 'SRV');
}

/// register `entry` (or with `remove`, withdraw it): one each
/// SEED_INTERVAL, waiting out the rate limit. Returns the registrar's
/// `{registered, conflict}`.
async function send(entry, remove) {
  await sleep(Math.max(0, last_registration + SEED_INTERVAL - Date.now()));
  try {
    return await patiently(entry.host, async () => {
      const addresses = [];
      if (!remove) {
        const hostname = new URL(entry.url).hostname;
        for (const type of ['A', 'AAAA']) {
          const answer = await sig0lease.lookup(config.doh, hostname, type);
          for (const record of answer.records) {
            if (record.type === type) {
              addresses.push(String(record.data));
            }
          }
        }
        if (addresses.length === 0) {
          throw new Error(hostname + ' has no address');
        }
      }
      // the key is kept before it signs, so a retry whose first answer the
      // rate limit took signs with the same key
      if (!entry.key) {
        entry.key = await sig0lease.newKey(entry.host + '.' + config.zone);
        keep(entry);
      }
      const url = new URL(entry.url);
      return sig0lease.register({
        doh: config.registrar,
        domain: config.zone,
        host: entry.host,
        addresses: addresses,
        instances: [{
          label: entry.host,
          service: FEDI_TYPE,
          subtypes: entry.subtypes,
          port: 443,
          txt: ['path=' + url.pathname, 'url=' + url.href],
        }],
        lease: LEASE,
        keyLease: LEASE,
        key: entry.key,
        remove: Boolean(remove),
      });
    });
  } finally {
    last_registration = Date.now();
  }
}

/// register `entry` and keep it; false when another key holds its name,
/// which forgets it
async function register_entry(entry) {
  const result = await send(entry, false);
  if (!result.registered) {
    forget(entry.host);
    return false;
  }
  entry.registered = Date.now();
  entry.due = renewal_time(entry.registered);
  entry.queued = false;
  keep(entry);
  postMessage({
    type: 'registered',
    name: instance_name(entry.host),
    subtypes: entry.subtypes,
  });
  return true;
}

/// register a kept entry again, before its lease ends
async function renew(entry) {
  if (entries.get(storage_key_of(entry.host)) !== entry) {
    return;  // removed or replaced meanwhile
  }
  try {
    if (!await register_entry(entry)) {
      console.warn('renewing ' + entry.host + ': another key holds it now');
    }
  } catch (error) {
    // try again soon, before the lease is out if it still can be
    console.warn('renewing ' + entry.host + ' failed', error);
    entry.queued = false;
    entry.due = Math.min(Date.now() + 30000,
                         entry.registered + LEASE * 1000 - 5000);
  }
}

/// seed one instance of INSTANCES_MD, unless the zone has it
async function seed_instance(instance) {
  try {
    const kept = entries.get(storage_key_of(instance.host));
    if (kept && kept.url) {
      // this browser keeps it: renewals take care of it
      seeding.existing++;
    } else if (await present(instance.host)) {
      seeding.existing++;
    } else {
      const entry = {
        host: instance.host,
        key: kept ? kept.key : null,
        url: instance.url.href,
        subtypes: instance.subtypes,
        registered: 0,
      };
      if (await register_entry(entry)) {
        seeding.registered++;
      } else {
        seeding.held++;  // someone else registered it
      }
    }
  } catch (error) {
    console.warn('registering ' + instance.url.href + ' failed', error);
    seeding.failed.push(instance.url.hostname + ': ' + error.message);
  }
  seeding.done++;
  seeding.running = seeding.done < seeding.total;
}

/// a visitor's add, edit or remove; answers with a 'done' message
async function visitor_request(message) {
  let error = null;
  try {
    if (message.type === 'add') {
      await add(instance_of(message.url, message.subtypes));
    } else if (message.type === 'edit') {
      await edit(message.host, instance_of(message.url, message.subtypes));
    } else {
      await remove(message.host);
    }
  } catch (e) {
    console.warn(message.type + ' failed', e);
    error = e.message;
  }
  postMessage({type: 'done', id: message.id, error: error});
}

/// register a new entry for `instance` ({host, url, subtypes})
async function add(instance) {
  const kept = entries.get(storage_key_of(instance.host));
  if ((kept && kept.url) || await present(instance.host)) {
    throw new Error(instance.url.hostname + ' is registered already');
  }
  const entry = {
    host: instance.host,
    key: kept ? kept.key : null,
    url: instance.url.href,
    subtypes: instance.subtypes,
    registered: 0,
  };
  if (!await register_entry(entry)) {
    throw new Error(instance.url.hostname + ' is held by someone else');
  }
}

/// change the entry at host label `host` to `instance`
async function edit(host, instance) {
  const entry = owned(host);
  if (instance.host !== host) {
    // another domain is another host: register it, then withdraw the old
    await add(instance);
    await remove(host);
    return;
  }
  const changed =
      {...entry, url: instance.url.href, subtypes: instance.subtypes};
  if (!await register_entry(changed)) {
    throw new Error(instance.url.hostname + ' is held by someone else now');
  }
}

/// withdraw the entry at host label `host`, KEY included
async function remove(host) {
  const entry = owned(host);
  const result = await send(entry, true);
  forget(host);
  if (!result.registered && result.conflict) {
    throw new Error(host + ' is held by someone else now');
  }
}

/// the entry this browser keeps at host label `host`
function owned(host) {
  const entry = entries.get(storage_key_of(host));
  if (!entry || !entry.key) {
    throw new Error('this browser has no key for ' + host);
  }
  return entry;
}
