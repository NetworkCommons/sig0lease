/// Fediverse Dashboard: registration worker
///
/// Runs in a Web Worker, beside the page, so the page keeps showing the zone
/// while it registers. It loads its own copy of the sig0lease WASM and
/// registers each instance of INSTANCES_MD (see `parse_instances`) that the
/// zone does not have yet, one each SEED_INTERVAL, for SEED_LEASE seconds:
/// as an SRP host named after the instance's domain (`chaos.social` ->
/// `chaos-social`), with the domain's addresses, and one `_fedi._tcp`
/// instance of the same label, on port 443, in the subtype of its project
/// (the INSTANCES_MD heading). The SRV record names the host in the zone, so
/// the TXT key `url` keeps the instance's own URL, which the dashboard links
/// to.
///
/// An instance is registered already when the dashboard shows it (the page
/// sends the names it shows after every refresh), or when its SRV record
/// answers, asked right before registering it. When the rate limit in front
/// of the proxy refuses a request, the worker waits SEED_RETRY_MIN, doubled
/// on each refusal up to SEED_RETRY_MAX, and tries the request again.
///
/// Messages from the page:
///   {type: 'registered', names}   the instance names the dashboard shows
///   {type: 'start', zone, doh, registrar, keys}
///                                 register in `zone`, asking `doh`, at the
///                                 SRP registrar `registrar`; `keys` are the
///                                 kept keys by their localStorage name
/// Messages to the page:
///   {type: 'status', state, text, title}
///   {type: 'key', storage_key, key}  a key to keep in localStorage
///   {type: 'registered', name, subtypes}  an instance this worker registered

importScripts('wasm_exec.js', 'services.js', 'fediverse.js');

/// folded names of the instances the dashboard shows
let shown = new Set();
let started = false;

self.onmessage = (event) => {
  const message = event.data;
  if (message.type === 'registered') {
    shown = new Set(message.names.map(fold));
  } else if (message.type === 'start' && !started) {
    started = true;
    run(message).catch((error) => {
      console.error('registering the listed instances failed', error);
      status('error', 'Registering instances failed: ' + error.message);
    });
  }
};

function status(state, text, title) {
  postMessage({type: 'status', state: state, text: text, title: title || ''});
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
async function patiently(what, f, progress) {
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
        status('waiting',
               progress() + ' · rate limited, continuing in ' + left + ' s');
        await sleep(1000);
      }
      wait = Math.min(wait * 2, SEED_RETRY_MAX);
    }
  }
}

/// register the instances of INSTANCES_MD the zone does not have yet
async function run({zone, doh, registrar, keys}) {
  status('loading', 'Loading the registration worker …');
  await load_wasm();
  const response = await fetch(INSTANCES_MD);
  if (!response.ok) {
    throw new Error(INSTANCES_MD + ': ' + response.status + ' ' +
                    response.statusText);
  }
  const listed = parse_instances(await response.text());

  let done = 0;
  let existing = 0;
  let registered = 0;
  let held = 0;
  const failed = [];
  const progress = () => 'Registering listed instances ' + done + '/' +
      listed.length + ' · ' + existing + ' registered already · ' +
      registered + ' new' + (held ? ' · ' + held + ' held by others' : '') +
      (failed.length ? ' · ' + failed.length + ' failed' : '');

  let last = 0;
  for (const instance of listed) {
    status(failed.length ? 'error' : 'loading', progress() + ' …',
           failed.join('\n'));
    const name = instance.host + '.' + FEDI_TYPE + '.' + zone;
    const what = instance.url.hostname;
    try {
      // the dashboard's list is up to a refresh old: ask the zone as well
      let present = shown.has(fold(name));
      if (!present) {
        const srv = await patiently(
            what, () => sig0lease.lookup(doh, name, 'SRV'), progress);
        present = srv.records.some(r => r.type === 'SRV');
      }
      if (present) {
        existing++;
      } else {
        // one registration each SEED_INTERVAL, counted from when the last
        // one was answered
        await sleep(Math.max(0, last + SEED_INTERVAL - Date.now()));
        const result = await patiently(
            what, () => register_instance(zone, doh, registrar, keys, instance),
            progress);
        last = Date.now();
        if (result.registered) {
          registered++;
          postMessage(
              {type: 'registered', name: name, subtypes: instance.subtypes});
        } else {
          // another key holds the name: someone else registered it
          held++;
        }
      }
    } catch (error) {
      console.warn('registering ' + instance.url.href + ' failed', error);
      failed.push(what + ': ' + error.message);
    }
    done++;
  }

  status(failed.length ? 'error' : 'ok',
         'Listed instances: ' + existing + ' registered already · ' +
             registered + ' registered for ' + SEED_LEASE / 60 + ' min' +
             (held ? ' · ' + held + ' held by others' : '') +
             (failed.length ? ' · ' + failed.length + ' failed' : ''),
         failed.join('\n'));
}

/// register one instance of INSTANCES_MD (see the top of this file)
async function register_instance(zone, doh, registrar, keys, instance) {
  const addresses = [];
  for (const type of ['A', 'AAAA']) {
    const answer = await sig0lease.lookup(doh, instance.url.hostname, type);
    for (const record of answer.records) {
      if (record.type === type) {
        addresses.push(String(record.data));
      }
    }
  }
  if (addresses.length === 0) {
    throw new Error(instance.url.hostname + ' has no address');
  }

  // the host's key, kept by the page, so this browser can register the
  // name again while its KEY is still there
  const storage_key = SEED_KEY_PREFIX + instance.host + '.' + zone;
  if (!keys[storage_key]) {
    keys[storage_key] = await sig0lease.newKey(instance.host + '.' + zone);
    postMessage({type: 'key', storage_key: storage_key, key: keys[storage_key]});
  }
  const result = await sig0lease.register({
    doh: registrar,
    domain: zone,
    host: instance.host,
    addresses: addresses,
    instances: [{
      label: instance.host,
      service: FEDI_TYPE,
      subtypes: instance.subtypes,
      port: 443,
      txt: ['path=' + instance.url.pathname, 'url=' + instance.url.href],
    }],
    lease: SEED_LEASE,
    keyLease: SEED_LEASE,
    key: keys[storage_key],
  });
  return result;
}
