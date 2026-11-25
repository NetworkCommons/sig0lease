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
///   <service instance> SRV + TXT             -> instance details
///
/// To keep the number of queries low, all known projects are only asked
/// every FULL_SCAN_EVERY refreshes, or when an unseen instance appears;
/// in between only the subtypes that had instances are asked again.

const REFRESH_INTERVAL = 5000;
const FULL_SCAN_EVERY = 6;
const FEDI_TYPE = '_fedi._tcp';
const ICON_DIR = 'icons/';
const SOURCES_CSV = ICON_DIR + 'sources.csv';
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
  constructor(doh, zone_doh, public_doh) {
    this.doh = doh;
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

    // reset UI and state
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
      const groups = await this.collect(this.dns, this.zone, generation);
      if (generation !== this.generation) {
        return;
      }
      this.render(groups);
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
    const base = FEDI_TYPE + '.' + zone;
    const [base_answers, service_answers] = await Promise.all([
      dns.query(base, 'PTR', true),
      // a zone may not list its service types; that's no failure
      dns.query('_services._dns-sd._udp.' + zone, 'PTR'),
    ]);
    const base_names = unique(base_answers.map(a => normalize_name(a.data)));

    // subtypes to ask: on a full scan, or when an unseen instance shows up,
    // all known projects, else those that had instances
    const full_scan = this.refreshes++ % FULL_SCAN_EVERY === 0 ||
        base_names.some(name => !this.seen.has(name));
    const subtypes = new Map();
    const add = (label) => {
      if (label && !subtypes.has(fold(label))) {
        subtypes.set(fold(label), label);
      }
    };
    if (full_scan) {
      this.projects.list.forEach(p => add(p.name));
    }
    for (const member of this.members.values()) {
      if (member.instances.size > 0) {
        add(member.label);
      }
    }
    for (const answer of service_answers) {
      const labels = split_labels(normalize_name(answer.data));
      if (labels.length > 4 && labels[1] === '_sub' &&
          (labels[2] + '.' + labels[3]).toLowerCase() === FEDI_TYPE) {
        add(decode_label(labels[0]));
      }
    }

    // ask the subtypes; a failed one keeps its last known instances
    await Promise.all([...subtypes].map(async ([key, label]) => {
      const owner = encode_label(label) + '._sub.' + base;
      try {
        const answers = await dns.query(owner, 'PTR', true);
        const previous = this.members.get(key);
        this.members.set(key, {
          // keep the spelling the project list or the zone gave first
          label: previous ? previous.label : label,
          instances: new Set(answers.map(a => normalize_name(a.data))),
        });
      } catch (error) {
        console.warn('subtype ' + owner + ' failed', error);
      }
    }));
    if (generation !== this.generation) {
      return [];
    }

    // every instance: listed under the base type or under a subtype
    const names = new Set(base_names);
    for (const member of this.members.values()) {
      member.instances.forEach(name => names.add(name));
    }
    const details = new Map(
        await Promise.all([...names].map(async (name) => {
          const [srv, txt] = await Promise.all(
              [dns.query(name, 'SRV', true), dns.query(name, 'TXT', true)]);
          return [name, {
            name: name,
            label: decode_label(split_labels(name)[0]),
            srv: srv.map(a => a.data)
                     .sort((a, b) => a.priority - b.priority ||
                               b.weight - a.weight),
            txt: txt,
          }];
        })));
    this.seen = names;

    // group the instances per project; instances of no subtype go to OTHER
    const groups = [];
    const grouped = new Set();
    for (const [key, member] of this.members) {
      if (member.instances.size === 0) {
        continue;
      }
      member.instances.forEach(name => grouped.add(name));
      groups.push({
        key: key,
        label: member.label,
        owner: encode_label(member.label) + '._sub.' + base,
        instances: [...member.instances].map(name => details.get(name)),
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
      const signature = JSON.stringify(
          group.instances.map(i => [i.name, i.srv, txt_strings(i.txt)]));
      let box = existing.get(group.key);
      existing.delete(group.key);
      if (!box || box.dataset.signature !== signature) {
        const fresh = this.create_box(group, !box && !initial);
        fresh.dataset.signature = signature;
        if (box) {
          box.replaceWith(fresh);
        }
        box = fresh;
      }
      ordered.push(box);
    }

    // remove vanished projects
    for (const [key, box] of existing) {
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

    return box;
  }

  /// create a service instance entry
  create_entry(instance, appearance) {
    const li = clone_template('entry-template');
    li.querySelector('.label').textContent = instance.label;
    li.querySelector('.label').title = instance.name;

    // `_fedi` follows `_http`: SdServiceInfo constructs the link
    const srv = instance.srv[0];
    const link = srv ? this.service_info.create_link(
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

/// UTF-8 text to a label in presentation format, every octet but letters,
/// digits, `-` and `_` escaped as `\DDD`
function encode_label(text) {
  let label = '';
  for (const octet of new TextEncoder().encode(text.normalize('NFC'))) {
    const c = String.fromCharCode(octet);
    label += /[A-Za-z0-9_-]/.test(c) ? c :
                                       '\\' + String(octet).padStart(3, '0');
  }
  return label;
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
