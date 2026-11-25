/// Fediverse DNS-SD Dashboard UI Logic
///
/// Polls the fediverse services of a zone and renders one box per fediverse
/// project, listing the service instances registered for it.
///
/// Fediverse services use the custom DNS-SD service type `_fedi._tcp`, which
/// follows the specification of `_http._tcp` (SRV port 443 is linked as
/// https, the TXT key `path` is the link's path). Each fediverse project has
/// its own subtype, named after the project's UTF-8 name (e.g. `Mastodon`,
/// `Takahē`, `GNU social`), so all Mastodon servers of a zone are listed at
///   Mastodon._sub._fedi._tcp.<zone>
///
/// DNS-SD has no way to enumerate the subtypes of a service type, so the
/// dashboard asks for the subtype of every project it knows from
/// `icons/sources.csv`, and for every `_fedi._tcp` subtype the zone lists in
/// `_services._dns-sd._udp.<zone>`.
///
/// Query chain per refresh:
///   _fedi._tcp.<zone> PTR                    -> all fediverse instances
///   _services._dns-sd._udp.<zone> PTR        -> subtypes the zone lists
///   <subtype>._sub._fedi._tcp.<zone> PTR     -> instances of a project
///                                               (the label as UTF-8 octets)
///   <service instance> SRV + TXT             -> instance details
///
/// To keep the number of queries low (the proxy sits behind a rate limit),
/// a refresh asks the base type, and the subtypes only when it changed:
/// all known projects every FULL_SCAN_EVERY refreshes, or when an instance
/// appears that the registration worker did not announce; the subtypes of
/// the instances the worker announced; an instance that is gone is dropped
/// from its subtypes without asking. The SRV and TXT records of an instance
/// are asked when it appears, and DETAILS_PER_REFRESH of the others each
/// refresh, the longest unchecked first. All queries go through a Pacer:
/// at most `rate` per second, slowing down and trying again when the rate
/// limit refuses one. Until a refresh is done the page shows the last one.
///
/// When the page has loaded and shown the instances the zone has, a Web
/// Worker (SEED_WORKER) starts, which does all registering over SRP, one
/// registration each SEED_INTERVAL, each for LEASE seconds: what the
/// visitor adds, edits or removes in the boxes; the renewal of every entry
/// this browser has the key for, at 80 to 85% of its lease; and, for the
/// zone the page opened with, the instances listed in `icons/instances.md`
/// that the zone does not have yet. The dashboard hands the worker the
/// instances it shows after every refresh, so the worker skips those. The
/// browser's localStorage keeps each entry and its key (`entry_key`).

const REFRESH_INTERVAL = 5000;
const FULL_SCAN_EVERY = 12;
/// SRV and TXT records of known instances asked again per refresh
const DETAILS_PER_REFRESH = 5;
/// queries per second of a refresh: at first, at least and at most; after a
/// refusal of the rate limit, the rate halves and queries pause QUERY_PAUSE ms
const QUERY_RATE = 10;
const QUERY_RATE_MIN = 1;
const QUERY_RATE_MAX = 25;
const QUERY_PAUSE = 3000;
const FEDI_TYPE = '_fedi._tcp';
const ICON_DIR = 'icons/';
const SOURCES_CSV = ICON_DIR + 'sources.csv';
const INSTANCES_MD = ICON_DIR + 'instances.md';
/// lease of the entries the worker registers, and of their keys, so the
/// names are free again when the entries are not renewed
const LEASE = 300;
/// the script of the registration worker
const SEED_WORKER = 'fediverse-seed-worker.js';
/// time between two registrations, in ms
const SEED_INTERVAL = 1000;
/// wait after the rate limit refused a request, in ms, doubled up to the max
const SEED_RETRY_MIN = 5000;
const SEED_RETRY_MAX = 60000;
/// localStorage prefix of the entries this browser registered, see
/// `entry_key`; OLD_KEY_PREFIX kept their keys alone, before
const ENTRY_PREFIX = 'fediverse-entry:';
const OLD_KEY_PREFIX = 'fediverse-seed-key:';
/// box key of the instances that are in no subtype
const OTHER = '';

/// accent colors of the well-known fediverse projects, by `slug` of
/// sources.csv: the main color of the project's logo or web site.
/// Projects without a color here get a random color.
const PROJECT_COLORS = {
  'fediverse': '#7a3db8',
  'mastodon': '#6364ff',
  'misskey': '#86b300',
  'pixelfed': '#e0287c',
  'peertube': '#f1680d',
  'lemmy': '#00bc8c',
  'writefreely': '#292929',
  'nodebb': '#1e5ebc',
  'mobilizon': '#ffd599',
  'pleroma': '#fba457',
  'loops': '#ffe500',
  'bookwyrm': '#2c43c4',
  'wordpress': '#21759b',
  'sharkey': '#1b98c5',
  'neodb': '#4d8fcb',
  'akkoma': '#462d7a',
  'piefed': '#0d6efd',
  'friendica': '#1872a2',
  'hometown': '#3c8f6e',
  'hubzilla': '#43488a',
  'wafrn': '#3b82f6',
  'mbin': '#d61aa8',
  'ghost': '#15171a',
  'gancio': '#e5141a',
  'cherrypick': '#e75c9a',
  'plume': '#6e66ae',
  'iceshrimp': '#8372f5',
  'funkwhale': '#009fe3',
  'bonfire': '#fae932',
  'vernissage': '#242424',
  'catodon': '#bd7cf7',
  'emissary': '#4f46e5',
  'gotosocial': '#df8957',
  'firefish': '#ed496d',
  'mitra': '#a85a9e',
  'forgejo': '#ff6600',
  'takahe': '#f15628',
  'manyfold': '#553d8f',
  'owncast': '#7871ff',
  'foundkey': '#a21c39',
  'hollo': '#1f1f1f',
  'pumpio': '#5a5a5a',
  'betula': '#0099e5',
  'diaspora': '#231f20',
  'gnusocial': '#a22430',
  'discourse': '#f15d22',
  'bridgy-fed': '#4a8cff',
  'socialhome': '#3088d4',
  'smithereen': '#4c6e00',
};

/// The fediverse projects of `icons/sources.csv`: name, logo and color
class FediProjects {
  constructor() {
    /// projects in the order of sources.csv: {slug, name, icon, color}
    this.list = [];
    /// folded name or slug -> project
    this.by_key = new Map();
    /// the general fediverse project, for instances without a project
    this.fediverse = null;
  }

  /// load the projects from the CSV file at `url`
  async load(url) {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(url + ': ' + response.status + ' ' + response.statusText);
    }
    const rows = parse_csv(await response.text());
    const header = rows.shift().map(h => h.trim());
    const column = (row, name) => (row[header.indexOf(name)] || '').trim();
    for (const row of rows) {
      const project = {
        slug: column(row, 'slug'),
        name: column(row, 'name'),
        icon: column(row, 'icon'),
      };
      if (!project.slug || !project.name) {
        continue;
      }
      project.color = PROJECT_COLORS[project.slug] || null;
      if (project.slug === 'fediverse') {
        this.fediverse = project;
        continue;
      }
      this.list.push(project);
      this.by_key.set(fold(project.name), project);
      if (!this.by_key.has(fold(project.slug))) {
        this.by_key.set(fold(project.slug), project);
      }
    }
  }

  /// the project of a subtype label, or null if it is not well-known
  find(label) {
    return this.by_key.get(fold(label)) || null;
  }

  /// title, colors and logo URL of the box of a subtype label, or of the
  /// instances without a subtype for OTHER
  appearance(label) {
    const project = label === OTHER ? this.fediverse : this.find(label);
    const name = label === OTHER ? 'Other Fediverse Services' :
                                   (project ? project.name : label);
    const rgb = project && project.color ? hex_2_rgb(project.color) :
                                           random_color(fold(label));
    const icon = project && project.icon ? project.icon :
        this.fediverse && this.fediverse.icon ? this.fediverse.icon :
                                                null;
    return {
      name: name,
      color: 'rgb(' + rgb.join(', ') + ')',
      on_color: on_color(rgb),
      icon: icon ? ICON_DIR + icon : null,
    };
  }
}

class FediverseDashboard {
  /// `doh` is the DNS-over-HTTPS server of the sig0lease proxy all queries go
  /// to, as a URL without path. If it is empty, a zone's queries go to the
  /// first of these that answers DoH: the page's origin, the proxies of
  /// `zone_doh` (`[{domain, doh}]`) whose `domain` is the zone or above it,
  /// and else to the public resolver `public_doh`.
  ///
  /// Registering (adding, editing, renewing, see SEED_WORKER) goes to the
  /// SRP registrar `registrar` (a DoH URL), by default the DoH server of the
  /// zone. `seed`: also register the instances of INSTANCES_MD missing in
  /// the first zone shown.
  constructor(doh, zone_doh, public_doh, seed, registrar) {
    this.doh = doh;
    this.seed_pending = Boolean(seed);
    this.registrar = registrar;
    // the registration worker of the current zone, once it started
    this.worker = null;
    this.worker_pending = false;
    // storage key -> entry this browser registered (see `entry_key`)
    this.entries = new Map();
    // id -> resolve of a visitor's request to the worker
    this.requests = new Map();
    this.request_id = 0;
    // folded subtype label -> label: subtypes of instances the worker
    // registered, asked on the next refresh
    this.hinted = new Map();
    // folded names of the instances the worker registered, which need no
    // full subtype scan when they appear
    this.expected = new Set();
    // instance name -> its SRV and TXT records and when they were asked
    this.details = new Map();
    this.pacer = new Pacer(QUERY_RATE, QUERY_RATE_MIN, QUERY_RATE_MAX,
                           QUERY_PAUSE);
    this.zone_doh = zone_doh || [];
    this.public_doh = public_doh;
    // DoH server -> promise of whether it answers DoH, each asked once
    this.probes = new Map();
    this.zone = null;
    this.dns = null;
    this.timer = null;
    this.service_info = new SdServiceInfo();
    this.projects = new FediProjects();
    this.projects_loaded = this.projects.load(SOURCES_CSV).catch((error) => {
      console.error('fediverse projects did not load', error);
    });
    // incremented on every zone change, so stale refreshes can be dropped
    this.generation = 0;
    // refreshes of the current zone, to schedule the full subtype scans
    this.refreshes = 0;
    // folded subtype label -> {label, instances: Set of instance names}
    this.members = new Map();
    // all instance names of the last refresh, to notice new instances
    this.seen = new Set();
    // instance names seen per box, to highlight new entries
    this.known = new Map();
    // nothing is highlighted on the first render of a zone
    this.first_render = true;

    this.boxes = document.getElementById('boxes');
    this.status = document.getElementById('status');
    this.status_text = document.getElementById('status-text');
    this.dnssec = document.getElementById('dnssec');
    this.empty = document.getElementById('empty');
    this.seed_status = document.getElementById('seed');
  }

  /// start watching a zone
  set_zone(zone) {
    zone = normalize_name(zone).toLowerCase();
    if (!zone || zone === this.zone) {
      return;
    }
    this.zone = zone;
    this.generation++;
    clearTimeout(this.timer);

    // reset UI and state; each zone has its own worker, started after its
    // first complete refresh
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.worker_pending = true;
    for (const [id, resolve] of this.requests) {
      resolve('the zone changed');
    }
    this.requests.clear();
    this.seed_status.hidden = true;
    this.hinted.clear();
    this.expected.clear();
    this.details.clear();
    this.refreshes = 0;
    this.members.clear();
    this.seen.clear();
    this.known.clear();
    this.first_render = true;
    this.boxes.replaceChildren();
    this.empty.hidden = true;
    this.dnssec.hidden = true;
    this.set_status('loading', 'Loading ' + zone + ' …');
    document.title = zone + ' · Fediverse Dashboard';

    const generation = this.generation;
    this.dns = new Dns(zone, this.choose_server(zone), (dns) => {
      if (generation === this.generation) {
        this.dnssec.hidden = !dns.dnssec_enabled;
      }
    });

    this.refresh();
  }

  /// start the registration worker for `zone` (see SEED_WORKER), after the
  /// first refresh showed what the zone has
  async start_worker(zone) {
    const {doh, is_public} = await this.choose_server(zone);
    const registrar = this.registrar || (is_public ? null : doh);
    if (!registrar) {
      console.info('no sig0lease proxy for ' + zone + ', nothing is registered');
      return;
    }
    if (zone !== this.zone || this.worker) {
      return;
    }
    // the worker has no localStorage: it gets the entries of the zone, and
    // sends the entries to keep
    this.entries = load_entries(zone);
    for (const entry of this.entries.values()) {
      if (!entry.url) {
        // only a key, kept before entries were: take the rest from the zone
        const instance = this.details.get(entry.host + '.' + FEDI_TYPE + '.' + zone);
        if (instance) {
          const url = this.service_info.txt_2_object(instance.txt).url;
          if (typeof url === 'string' && /^https?:\/\//i.test(url)) {
            entry.url = url;
            entry.subtypes = [...this.members.values()]
                                 .filter(m => m.instances.has(instance.name))
                                 .map(m => m.label);
          }
        }
      }
    }
    const seed = this.seed_pending;
    this.seed_pending = false;
    this.worker = new Worker(SEED_WORKER);
    this.worker.onmessage = (event) => this.on_seed_message(event.data);
    this.worker.onerror = (event) => {
      event.preventDefault();
      this.set_seed_status('error', 'Registering failed: ' +
                                        (event.message || 'worker error'));
    };
    this.worker.postMessage({type: 'registered', names: [...this.seen]});
    this.worker.postMessage({
      type: 'start',
      zone: zone,
      doh: doh,
      registrar: registrar,
      entries: Object.fromEntries(this.entries),
      seed: seed,
    });
    // the boxes get their add and edit buttons
    this.redraw();
  }

  /// a message of the registration worker
  on_seed_message(message) {
    switch (message.type) {
      case 'status':
        this.set_seed_status(message.state, message.text, message.title);
        break;
      case 'entry':
        this.entries.set(message.storage_key, message.entry);
        localStorage.setItem(message.storage_key, JSON.stringify(message.entry));
        break;
      case 'forget':
        this.entries.delete(message.storage_key);
        localStorage.removeItem(message.storage_key);
        this.redraw();
        break;
      case 'registered':
        this.expected.add(fold(message.name));
        for (const subtype of message.subtypes) {
          this.hinted.set(fold(subtype), subtype);
        }
        this.redraw();
        break;
      case 'done': {
        const resolve = this.requests.get(message.id);
        this.requests.delete(message.id);
        if (resolve) {
          resolve(message.error);
        }
        break;
      }
    }
  }

  /// ask the worker to add, edit or remove an entry; resolves to null when
  /// done, or to an error message
  request(message) {
    if (!this.worker) {
      return Promise.resolve('registering is not available for this zone');
    }
    const id = ++this.request_id;
    return new Promise((resolve) => {
      this.requests.set(id, resolve);
      this.worker.postMessage({...message, id: id});
    });
  }

  /// whether this browser has the key of `instance`, so it can edit it
  owns(instance) {
    return this.worker !== null &&
        this.entries.has(entry_key(fold(instance.label), this.zone));
  }

  /// render the last groups again, e.g. when buttons change
  redraw() {
    if (this.groups) {
      this.render(this.groups);
    }
  }

  set_seed_status(state, text, title) {
    this.seed_status.dataset.state = state;
    this.seed_status.textContent = text;
    this.seed_status.title = title || '';
    this.seed_status.hidden = false;
  }

  /// choose the DoH server for `zone`, as the constructor describes, and
  /// return `{doh, is_public}`
  async choose_server(zone) {
    if (this.doh) {
      return {doh: this.doh, is_public: false};
    }
    const candidates = [];
    if (location.protocol === 'https:' || location.protocol === 'http:') {
      candidates.push(location.origin);
    }
    for (const {domain, doh} of this.zone_doh) {
      if (zone === domain || zone.endsWith('.' + domain)) {
        candidates.push(doh);
      }
    }
    for (const doh of candidates) {
      if (await this.answers_doh(doh)) {
        return {doh, is_public: false};
      }
    }
    return {doh: this.public_doh, is_public: true};
  }

  /// whether `doh` answers a DoH question; asked once per server
  answers_doh(doh) {
    if (!this.probes.has(doh)) {
      // a proxy hands a name it does not serve, as the root, to a public
      // resolver, so only a server that speaks no DoH fails
      this.probes.set(
          doh,
          sig0lease.lookup(doh, '.', 'SOA').then(() => true, (error) => {
            console.warn(doh + ' is no DoH server', error);
            return false;
          }));
    }
    return this.probes.get(doh);
  }

  /// query the zone and re-render, then schedule the next refresh
  async refresh() {
    const generation = this.generation;
    await this.projects_loaded;
    try {
      this.dns.cached_answers = 0;
      const refusals = this.pacer.refusals;
      const groups = await this.collect(this.dns, this.zone, generation);
      if (generation !== this.generation) {
        return;
      }
      this.groups = groups;
      this.render(groups);
      // the worker starts once the instances the zone has are shown, and
      // skips those
      if (this.worker_pending && this.complete) {
        this.worker_pending = false;
        this.start_worker(this.zone).catch((error) => {
          console.error('the registration worker did not start', error);
          this.set_seed_status('error', 'Registering failed: ' + error.message);
        });
      }
      if (this.worker) {
        this.worker.postMessage({type: 'registered', names: [...this.seen]});
      }
      const projects = groups.filter(g => g.key !== OTHER).length;
      this.set_status(
          'ok',
          plural(projects, 'project') + ' · ' +
              plural(this.seen.size, 'instance') + ' · updated ' +
              new Date().toLocaleTimeString() + ' from ' +
              new URL(this.dns.doh).host +
              (this.dns.cached_answers ?
                   ' · ' + plural(this.dns.cached_answers, 'answer') +
                       ' via public resolver (may be cached)' :
                   '') +
              (this.pacer.refusals > refusals ?
                   ' · rate limited, slowed to ' +
                       this.pacer.rate.toFixed(1) + ' queries/s' :
                   ''));
    } catch (error) {
      if (generation !== this.generation) {
        return;
      }
      console.error(error);
      this.set_status(
          'error',
          'Update failed at ' + new Date().toLocaleTimeString() +
              ', showing last known state');
    }
    this.timer = setTimeout(() => this.refresh(), REFRESH_INTERVAL);
  }

  /// collect the fediverse instances of a zone, their SRV and TXT records,
  /// grouped by project: an array of `{key, label, owner, instances}`
  async collect(dns, zone, generation) {
    const query = (name, type) =>
        this.pacer.run(() => dns.query(name, type, true));
    const base = FEDI_TYPE + '.' + zone;
    const base_names = unique((await query(base, 'PTR'))
                                  .map(a => normalize_name(a.data)));
    const current = new Set(base_names);

    // subtypes to ask: all known projects on a full scan, or when an
    // instance appears that the worker did not announce; else those of the
    // instances the worker announced
    const added = base_names.filter(name => !this.seen.has(name));
    const full_scan = this.refreshes++ % FULL_SCAN_EVERY === 0 ||
        added.some(name => !this.expected.has(fold(name)));
    const subtypes = new Map();
    const add = (label) => {
      if (usable_label(label) && !subtypes.has(fold(label))) {
        subtypes.set(fold(label), label);
      }
    };
    if (full_scan) {
      this.projects.list.forEach(p => add(p.name));
      for (const member of this.members.values()) {
        add(member.label);
      }
      // a zone may list the subtypes in its service types
      try {
        for (const answer of await query(
                 '_services._dns-sd._udp.' + zone, 'PTR')) {
          const labels = split_labels(normalize_name(answer.data));
          if (labels.length > 4 && labels[1] === '_sub' &&
              (labels[2] + '.' + labels[3]).toLowerCase() === FEDI_TYPE) {
            add(decode_label(labels[0]));
          }
        }
      } catch (error) {
        console.warn('service types of ' + zone + ' failed', error);
      }
    }
    for (const label of this.hinted.values()) {
      add(label);
    }

    // ask the subtypes; a failed one keeps its last known instances
    await Promise.all([...subtypes].map(async ([key, label]) => {
      const owner = encode_label(label) + '._sub.' + base;
      try {
        const answers = await query(owner, 'PTR');
        const previous = this.members.get(key);
        this.members.set(key, {
          // keep the spelling the project list or the zone gave first
          label: previous ? previous.label : label,
          instances: new Set(answers.map(a => normalize_name(a.data))),
        });
        this.hinted.delete(key);
      } catch (error) {
        console.warn('subtype ' + owner + ' failed', error);
      }
    }));
    if (generation !== this.generation) {
      return [];
    }
    // an instance gone from the base type is gone from its subtypes
    for (const member of this.members.values()) {
      for (const name of member.instances) {
        if (!current.has(name)) {
          member.instances.delete(name);
        }
      }
    }

    // SRV and TXT records: of new instances, and of the longest unchecked
    // others; an instance whose records were never answered is left out
    // until they are
    for (const name of this.details.keys()) {
      if (!current.has(name)) {
        this.details.delete(name);
      }
    }
    const unknown = base_names.filter(name => !this.details.has(name));
    const recheck = base_names.filter(name => this.details.has(name))
                        .sort((a, b) => this.details.get(a).checked -
                                  this.details.get(b).checked)
                        .slice(0, DETAILS_PER_REFRESH);
    await Promise.all([...unknown, ...recheck].map(async (name) => {
      try {
        const [srv, txt] =
            await Promise.all([query(name, 'SRV'), query(name, 'TXT')]);
        this.details.set(name, {
          name: name,
          label: decode_label(split_labels(name)[0]),
          srv: srv.map(a => a.data)
                   .sort((a, b) => a.priority - b.priority ||
                             b.weight - a.weight),
          txt: txt,
          checked: Date.now(),
        });
      } catch (error) {
        console.warn('records of ' + name + ' failed', error);
      }
    }));
    if (generation !== this.generation) {
      return [];
    }
    const details = this.details;
    const names = new Set(base_names.filter(name => details.has(name)));
    this.seen = names;
    // the refresh is complete when every instance has its records
    this.complete = names.size === base_names.length;

    // group the instances per project; instances of no subtype go to OTHER
    const groups = [];
    const grouped = new Set();
    for (const [key, member] of this.members) {
      const instances = [...member.instances].filter(name => names.has(name));
      instances.forEach(name => grouped.add(name));
      if (instances.length === 0) {
        continue;
      }
      groups.push({
        key: key,
        label: member.label,
        owner: encode_label(member.label) + '._sub.' + base,
        instances: instances.map(name => details.get(name)),
      });
    }
    const others = [...names].filter(name => !grouped.has(name));
    if (others.length > 0) {
      groups.push({
        key: OTHER,
        label: OTHER,
        owner: base,
        instances: others.map(name => details.get(name)),
      });
    }
    for (const group of groups) {
      group.instances.sort((a, b) => a.label.localeCompare(b.label));
    }
    return groups;
  }

  /// update the boxes, only touching boxes whose content changed
  render(groups) {
    // alphabetical by project name, the instances of no project last
    const titles = new Map(
        groups.map(g => [g.key, this.projects.appearance(g.label).name]));
    groups.sort((a, b) => (a.key === OTHER) - (b.key === OTHER) ||
                    titles.get(a.key).localeCompare(titles.get(b.key)));

    const existing = new Map();
    for (const box of this.boxes.children) {
      existing.set(box.dataset.key, box);
    }

    const initial = this.first_render;
    this.first_render = false;
    const ordered = [];
    for (const group of groups) {
      const signature = JSON.stringify([
        this.worker !== null,
        group.instances.map(
            i => [i.name, i.srv, txt_strings(i.txt), this.owns(i)]),
      ]);
      let box = existing.get(group.key);
      existing.delete(group.key);
      // a box with an open form stays until the form closes
      const editing = box && box.querySelector('.instance-form');
      if (!editing && (!box || box.dataset.signature !== signature)) {
        const fresh = this.create_box(group, !box && !initial);
        fresh.dataset.signature = signature;
        if (box) {
          box.replaceWith(fresh);
        }
        box = fresh;
      }
      ordered.push(box);
    }

    // remove vanished projects, unless a form is open in one
    for (const [key, box] of existing) {
      if (box.querySelector('.instance-form')) {
        ordered.push(box);
        continue;
      }
      box.remove();
      this.known.delete(key);
    }
    // keep the order, appendChild moves existing nodes
    for (const box of ordered) {
      this.boxes.appendChild(box);
    }

    this.empty.hidden = groups.length > 0;
  }

  /// create a project box
  create_box(group, is_new_box) {
    const box = clone_template('box-template');
    box.dataset.key = group.key;
    if (is_new_box) {
      box.classList.add('new');
    }

    // title row: project logo, name and accent color
    const appearance = this.projects.appearance(group.label);
    box.style.setProperty('--accent', appearance.color);
    box.style.setProperty('--on-accent', appearance.on_color);
    box.querySelector('.service-icon').appendChild(create_logo(appearance));
    box.querySelector('.name').textContent = appearance.name;
    const subtype = box.querySelector('.subtype');
    if (group.key === OTHER) {
      subtype.hidden = true;
    } else {
      subtype.textContent = group.label;
      subtype.title = 'DNS-SD subtype';
    }
    box.querySelector('.service').textContent = FEDI_TYPE;
    box.querySelector('.count').textContent = group.instances.length;
    box.querySelector('.fqdn').textContent = group.owner;

    // remember which instances were already visible
    const previous = this.known.get(group.key);
    const ul = box.querySelector('.entries');
    for (const instance of group.instances) {
      const li = this.create_entry(instance, appearance);
      if (previous && !previous.has(instance.name)) {
        li.classList.add('new');
      }
      ul.appendChild(li);
    }
    this.known.set(group.key, new Set(group.instances.map(i => i.name)));

    // a new entry in this box's project
    if (this.worker) {
      const actions = box.querySelector('.box-actions');
      actions.hidden = false;
      const button = actions.querySelector('.add-button');
      button.addEventListener('click', () => {
        if (actions.querySelector('.instance-form')) {
          return;
        }
        const subtypes = group.key === OTHER ? [] : [group.label];
        actions.appendChild(this.create_form({
          mode: 'add',
          url: '',
          subtypes: subtypes,
          done: () => this.redraw(),
        }));
      });
    }

    return box;
  }

  /// a form to add (`mode` 'add') or edit (`mode` 'edit', of the entry at
  /// host label `host`) an entry: its URL, and when editing its project.
  /// `done` is called when the form closes.
  create_form({mode, host, url, subtypes, done}) {
    const form = clone_template('form-template');
    const input = form.querySelector('input[name="url"]');
    const select = form.querySelector('select[name="project"]');
    const message = form.querySelector('.form-message');
    const remove = form.querySelector('.remove');
    input.value = url;
    form.querySelector('.save-text').textContent =
        mode === 'add' ? 'Add' : 'Save';

    if (mode === 'edit') {
      // the projects, with this entry's first; '' is no project
      const options = [['', 'No project (Other)']];
      for (const project of [...this.projects.list].sort(
               (a, b) => a.name.localeCompare(b.name))) {
        options.push([project.name, project.name]);
      }
      for (const subtype of subtypes) {
        if (!options.some(([value]) => fold(value) === fold(subtype))) {
          options.push([subtype, subtype]);
        }
      }
      for (const [value, text] of options) {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = text;
        select.appendChild(option);
      }
      const current = subtypes.length ?
          options.find(([value]) => fold(value) === fold(subtypes[0])) :
          options[0];
      select.value = current ? current[0] : '';
      select.hidden = false;
      remove.hidden = false;
    }

    const close = () => {
      form.remove();
      done();
    };
    const busy = (text) => {
      for (const element of form.elements) {
        element.disabled = Boolean(text);
      }
      message.textContent = text || '';
      message.classList.remove('error');
    };
    const send = async (request, text) => {
      busy(text);
      const error = await this.request(request);
      if (error) {
        busy('');
        message.textContent = error;
        message.classList.add('error');
        return;
      }
      close();
    };

    form.addEventListener('submit', (event) => {
      event.preventDefault();
      let instance;
      try {
        const chosen = mode === 'add' ? subtypes :
            select.value ? [select.value] : [];
        instance = instance_of(input.value.trim(), chosen);
      } catch (error) {
        message.textContent = error.message;
        message.classList.add('error');
        return;
      }
      send(mode === 'add' ?
               {type: 'add', url: instance.url.href, subtypes: instance.subtypes} :
               {type: 'edit', host: host, url: instance.url.href,
                subtypes: instance.subtypes},
           mode === 'add' ? 'Registering …' : 'Saving …');
    });
    remove.addEventListener('click', () => {
      send({type: 'remove', host: host}, 'Removing …');
    });
    form.querySelector('.cancel').addEventListener('click', close);
    setTimeout(() => input.focus());
    return form;
  }

  /// create a service instance entry
  create_entry(instance, appearance) {
    const li = clone_template('entry-template');
    li.querySelector('.label').textContent = instance.label;
    li.querySelector('.label').title = instance.name;

    // the TXT key `url`, else as `_fedi` follows `_http`, the link
    // SdServiceInfo constructs
    const srv = instance.srv[0];
    const url = this.service_info.txt_2_object(instance.txt).url;
    const link = typeof url === 'string' && /^https?:\/\//i.test(url) ? url :
        srv ? this.service_info.create_link(
                  '_http', normalize_name(srv.target), srv.port,
                  instance.txt) :
              null;
    const link_node = li.querySelector('.link');
    if (link) {
      link_node.href = link;
      link_node.querySelector('.url').textContent = link;
      link_node.querySelector('.icon').appendChild(create_logo(appearance));
      link_node.hidden = false;
    }

    // SRV records
    const targets = li.querySelector('.targets');
    for (const record of instance.srv) {
      const div = document.createElement('div');
      div.className = 'target';
      div.textContent = normalize_name(record.target) + ':' + record.port;
      div.title = 'priority ' + record.priority + ', weight ' + record.weight;
      targets.appendChild(div);
    }
    if (instance.srv.length === 0) {
      const div = document.createElement('div');
      div.className = 'target missing';
      div.textContent = 'no SRV record';
      targets.appendChild(div);
    }

    // this browser has the key: the entry can be edited
    if (this.owns(instance)) {
      const host = fold(instance.label);
      const entry = this.entries.get(entry_key(host, this.zone));
      const button = li.querySelector('.edit-button');
      button.hidden = false;
      button.addEventListener('click', () => {
        if (li.querySelector('.instance-form')) {
          return;
        }
        const subtypes = entry && entry.url ? entry.subtypes :
            [...this.members.values()]
                .filter(m => m.instances.has(instance.name))
                .map(m => m.label);
        li.appendChild(this.create_form({
          mode: 'edit',
          host: host,
          url: entry && entry.url ? entry.url : (link || ''),
          subtypes: subtypes || [],
          done: () => this.redraw(),
        }));
      });
    }

    // TXT records as key/value chips
    const txt_node = li.querySelector('.txt');
    for (const entry of txt_strings(instance.txt)) {
      if (entry === '') {
        continue;
      }
      const span = document.createElement('span');
      span.textContent = entry;
      txt_node.appendChild(span);
    }

    return li;
  }

  set_status(state, text) {
    this.status.dataset.state = state;
    this.status_text.textContent = text;
  }
}

/// the logo of a box's `appearance`, or a generic icon if there is none
function create_logo(appearance) {
  if (!appearance.icon) {
    const span = document.createElement('span');
    span.className = 'fa-solid fa-circle-nodes';
    span.setAttribute('aria-hidden', 'true');
    return span;
  }
  const img = document.createElement('img');
  img.src = appearance.icon;
  img.alt = '';
  img.loading = 'lazy';
  return img;
}

/// the localStorage name of the entry at host label `host` in `zone`
function entry_key(host, zone) {
  return ENTRY_PREFIX + host + '.' + zone;
}

/// the entries of `zone` this browser keeps: storage key -> `{host, key,
/// url, subtypes, registered}`; a key kept alone under OLD_KEY_PREFIX
/// becomes an entry without url
function load_entries(zone) {
  const entries = new Map();
  const suffix = '.' + zone;
  for (let i = 0; i < localStorage.length; i++) {
    const name = localStorage.key(i);
    let value;
    try {
      value = JSON.parse(localStorage.getItem(name));
    } catch (error) {
      continue;
    }
    if (!value || !name.endsWith(suffix)) {
      continue;
    }
    if (name.startsWith(ENTRY_PREFIX)) {
      entries.set(name, value);
    } else if (name.startsWith(OLD_KEY_PREFIX) && value.public) {
      const host = name.slice(OLD_KEY_PREFIX.length, -suffix.length);
      const key = entry_key(host, zone);
      if (!entries.has(key)) {
        entries.set(key, {host: host, key: value, url: null, subtypes: [],
                          registered: 0});
      }
    }
  }
  return entries;
}

/// an entry to register for the URL `text` in the projects `subtypes`:
/// `{host, url, subtypes}`, `host` the host label of the URL's domain;
/// throws for what cannot be registered
function instance_of(text, subtypes) {
  let url;
  try {
    url = new URL(text);
  } catch (error) {
    throw new Error('not a URL: ' + text);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('not an http(s) URL: ' + text);
  }
  const host = url.hostname.toLowerCase().replace(/\./g, '-');
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) {
    throw new Error(url.hostname + ' makes no host label');
  }
  const labels = [];
  for (const subtype of subtypes) {
    if (!usable_label(subtype)) {
      throw new Error(subtype + ' makes no subtype label');
    }
    if (!labels.some(label => fold(label) === fold(subtype))) {
      labels.push(subtype);
    }
  }
  return {host: host, url: url, subtypes: labels};
}

/// the instances of INSTANCES_MD: `## <project>` headings, each followed by
/// a list of `- [name](url)` links. A heading starting with `_fedi` lists
/// general fediverse services, which get no subtype. An instance listed
/// twice is registered once, in the subtypes of both headings.
/// Returns `[{host, url, subtypes}]`, `host` the host label of the url's
/// domain.
function parse_instances(markdown) {
  const by_host = new Map();
  let project = null;
  for (const line of markdown.split(/\r?\n/)) {
    const heading = /^##\s+(.+?)\s*$/.exec(line);
    if (heading) {
      project = heading[1].startsWith('_fedi') ? null : heading[1];
      continue;
    }
    const link = /^\s*[-*]\s+\[[^\]]*\]\((https?:\/\/[^)\s]+)\)/.exec(line);
    if (!link) {
      continue;
    }
    let instance;
    try {
      instance = instance_of(link[1], project ? [project] : []);
    } catch (error) {
      console.warn(INSTANCES_MD + ': ' + error.message);
      continue;
    }
    const known = by_host.get(instance.host);
    if (!known) {
      by_host.set(instance.host, instance);
    } else if (instance.subtypes.length &&
               !known.subtypes.some(s => fold(s) === fold(instance.subtypes[0]))) {
      known.subtypes.push(instance.subtypes[0]);
    }
  }
  return [...by_host.values()];
}

/// whether `error` is the refusal of the rate limit in front of the proxy:
/// an error answer without CORS header, which the browser reports as a
/// failed fetch, or an HTTP status of a limit or an overloaded upstream
function rate_limited(error) {
  const message = String(error && error.message || error);
  return /Failed to fetch|cannot reach|answered (429|502|503|504)\b/i.test(
      message);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/// Paces requests: at most `rate` per second; when the rate limit refuses
/// one (`rate_limited`), the rate halves down to `min`, all requests pause
/// `pause` ms, and the refused one is sent again. Each answered request
/// raises the rate a little, up to `max`.
class Pacer {
  constructor(rate, min, max, pause) {
    this.rate = rate;
    this.min = min;
    this.max = max;
    this.pause = pause;
    // when the next request may go, in ms since the epoch
    this.next = 0;
    // requests the rate limit refused
    this.refusals = 0;
  }

  async run(f) {
    for (;;) {
      const now = Date.now();
      const at = Math.max(now, this.next);
      this.next = at + 1000 / this.rate;
      if (at > now) {
        await sleep(at - now);
      }
      try {
        const result = await f();
        this.rate = Math.min(this.max, this.rate + 0.1);
        return result;
      } catch (error) {
        if (!rate_limited(error)) {
          throw error;
        }
        this.refusals++;
        this.rate = Math.max(this.min, this.rate / 2);
        this.next = Math.max(this.next, Date.now() + this.pause);
      }
    }
  }
}

/// clone the first element of a template
function clone_template(id) {
  return document.getElementById(id).content.firstElementChild.cloneNode(true);
}

/// remove trailing dot and surrounding whitespace
function normalize_name(name) {
  return String(name).trim().replace(/\.$/, '');
}

/// a subtype label or project name for comparison: DNS compares ASCII
/// letters case-insensitively; the rest is normalized to NFC
function fold(label) {
  return String(label).normalize('NFC').toLowerCase();
}

/// split a domain name in presentation format into its labels, which keep
/// their escapes (`\.`, `\032`)
function split_labels(name) {
  const labels = [];
  let label = '';
  for (let i = 0; i < name.length; i++) {
    const c = name[i];
    if (c === '\\') {
      label += c + (name[i + 1] || '');
      i++;
    } else if (c === '.') {
      labels.push(label);
      label = '';
    } else {
      label += c;
    }
  }
  labels.push(label);
  return labels;
}

/// a label in presentation format (`Takah\196\147`, `GNU\032social`) to its
/// UTF-8 text (`Takahē`, `GNU social`)
function decode_label(label) {
  const encoder = new TextEncoder();
  const bytes = [];
  for (let i = 0; i < label.length; i++) {
    let c = label[i];
    if (c === '\\') {
      const digits = /^\d{3}/.exec(label.slice(i + 1));
      if (digits) {
        bytes.push(Number(digits[0]) & 0xff);
        i += 3;
        continue;
      }
      i++;
      c = label[i] || '';
    }
    bytes.push(...encoder.encode(c));
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

/// a subtype label or project name as the name of a query: the DNS library
/// of the WASM packs a name's labels as their octets, without escapes, so
/// the text goes as it is (`Takahē`, `GNU social`), and a label containing
/// `.` cannot be asked for (nor registered, see `usable_label`)
function encode_label(text) {
  return text.normalize('NFC');
}

/// whether a subtype label can be queried and registered: not empty, no
/// `.`, at most 63 octets
function usable_label(text) {
  const octets = new TextEncoder().encode(text.normalize('NFC')).length;
  return octets > 0 && octets <= 63 && !text.includes('.');
}

/// parse CSV text (RFC 4180, with quoted fields) into an array of rows
function parse_csv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      quoted = true;
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') {
        i++;
      }
      row.push(field);
      field = '';
      if (row.length > 1 || row[0] !== '') {
        rows.push(row);
      }
      row = [];
    } else {
      field += c;
    }
  }
  row.push(field);
  if (row.length > 1 || row[0] !== '') {
    rows.push(row);
  }
  return rows;
}

/// decode TXT answers to an array of strings
function txt_strings(txt_answers) {
  const decoder = new TextDecoder();
  const strings = [];
  for (const answer of txt_answers) {
    const data = Array.isArray(answer.data) ? answer.data : [answer.data];
    for (const entry of data) {
      strings.push(typeof entry === 'string' ? entry : decoder.decode(entry));
    }
  }
  return strings;
}

function unique(array) {
  return [...new Set(array)];
}

function plural(n, word) {
  return n + ' ' + word + (n === 1 ? '' : 's');
}
