/// DNS-SD Dashboard UI Logic
///
/// Polls the DNS-SD structure of a zone and renders one box per
/// service type, listing all service instances registered for it.
///
/// Query chain per refresh:
///   _services._dns-sd._udp.<zone> PTR  -> service types
///   <service type> PTR                 -> service instances
///   <service instance> SRV + TXT       -> instance details

const REFRESH_INTERVAL = 5000;
// localStorage key of the service types the user has hidden
const HIDDEN_STORAGE_KEY = 'dashboard.hidden_services';

class Dashboard {
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
    // incremented on every zone change, so stale refreshes can be dropped
    this.generation = 0;
    // instance names seen per service type, to highlight new entries
    this.known = new Map();
    // nothing is highlighted on the first render of a zone
    this.first_render = true;

    this.boxes = document.getElementById('boxes');
    this.status = document.getElementById('status');
    this.status_text = document.getElementById('status-text');
    this.dnssec = document.getElementById('dnssec');
    this.empty = document.getElementById('empty');
    this.all_hidden = document.getElementById('all-hidden');
    this.filters = document.getElementById('filters');
    // service types (`_service._protocol`) hidden by the user, kept across
    // zones and visits
    this.hidden = load_hidden();
    // last rendered service type list, to only rebuild changed filter tags
    this.filter_signature = null;
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

    // reset UI
    this.known.clear();
    this.first_render = true;
    this.boxes.replaceChildren();
    this.filters.replaceChildren();
    this.filters.hidden = true;
    this.filter_signature = null;
    this.empty.hidden = true;
    this.all_hidden.hidden = true;
    this.dnssec.hidden = true;
    this.set_status('loading', 'Loading ' + zone + ' …');
    document.title = zone + ' · DNS-SD Dashboard';

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
    try {
      this.dns.cached_answers = 0;
      const types = await this.collect(this.dns, this.zone);
      if (generation !== this.generation) {
        return;
      }
      this.render(types);
      const count = types.reduce((n, t) => n + t.instances.length, 0);
      this.set_status(
          'ok',
          plural(types.length, 'service type') + ' · ' +
              plural(count, 'instance') + ' · updated ' +
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

  /// collect service types, instances, SRV and TXT records of a zone
  async collect(dns, zone) {
    const type_answers =
        await dns.query('_services._dns-sd._udp.' + zone, 'PTR', true);
    const type_names = unique(type_answers.map(a => normalize_name(a.data)));

    return Promise.all(type_names.map(async (type_name) => {
      const instance_answers = await dns.query(type_name, 'PTR', true);
      const instance_names =
          unique(instance_answers.map(a => normalize_name(a.data)));
      const service = get_service(type_name);

      const instances = await Promise.all(instance_names.map(async (name) => {
        const [srv, txt] = await Promise.all(
            [dns.query(name, 'SRV', true), dns.query(name, 'TXT', true)]);
        return {
          name: name,
          label: instance_label(name, service),
          srv: srv.map(a => a.data)
                   .sort((a, b) => a.priority - b.priority ||
                             b.weight - a.weight),
          txt: txt,
        };
      }));
      instances.sort((a, b) => a.label.localeCompare(b.label));

      return {name: type_name, service: service, instances: instances};
    }));
  }

  /// update the boxes, only touching boxes whose content changed
  render(types) {
    types.sort((a, b) => a.name.localeCompare(b.name));

    const existing = new Map();
    for (const box of this.boxes.children) {
      existing.set(box.dataset.type, box);
    }

    const initial = this.first_render;
    this.first_render = false;
    const ordered = [];
    for (const type of types) {
      const signature = JSON.stringify(
          type.instances.map(i => [i.name, i.srv, txt_strings(i.txt)]));
      let box = existing.get(type.name);
      existing.delete(type.name);
      if (!box || box.dataset.signature !== signature) {
        const fresh = this.create_box(type, !box && !initial);
        fresh.dataset.signature = signature;
        if (box) {
          box.replaceWith(fresh);
        }
        box = fresh;
      }
      ordered.push(box);
    }

    // remove vanished service types
    for (const [name, box] of existing) {
      box.remove();
      this.known.delete(name);
    }
    // keep alphabetical order, appendChild moves existing nodes
    for (const box of ordered) {
      this.boxes.appendChild(box);
    }

    this.render_filters(types);
    this.apply_filters();
    this.empty.hidden = types.length > 0;
  }

  /// update the header tags, one per service type of the zone, which toggle
  /// the display of that service type
  render_filters(types) {
    const signature = JSON.stringify(
        types.map(t => [service_key(t.service), t.instances.length]));
    if (signature === this.filter_signature) {
      return;
    }
    this.filter_signature = signature;

    // service types can appear in several boxes, e.g. under subdomains
    const tags = new Map();
    for (const type of types) {
      const key = service_key(type.service);
      const tag = tags.get(key);
      if (tag) {
        tag.count += type.instances.length;
      } else {
        tags.set(key, {service: type.service, count: type.instances.length});
      }
    }

    const buttons = [];
    for (const [key, tag] of tags) {
      const appearance = this.service_info.appearance(tag.service.service);
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'filter';
      button.dataset.key = key;
      button.style.setProperty('--accent', appearance.color);
      button.style.setProperty('--on-accent', appearance.on_color);
      button.title = key + ' · ' + plural(tag.count, 'instance');
      button.appendChild(this.service_info.create_icon(tag.service.service));
      const name = document.createElement('span');
      name.className = 'filter-name';
      name.textContent = appearance.name;
      button.appendChild(name);
      const count = document.createElement('span');
      count.className = 'filter-count';
      count.textContent = tag.count;
      button.appendChild(count);
      button.addEventListener('click', () => this.toggle_service(key));
      buttons.push(button);
    }
    this.filters.replaceChildren(...buttons);
    this.filters.hidden = buttons.length === 0;
  }

  /// show or hide a service type
  toggle_service(key) {
    if (this.hidden.has(key)) {
      this.hidden.delete(key);
    } else {
      this.hidden.add(key);
    }
    save_hidden(this.hidden);
    this.apply_filters();
  }

  /// hide the boxes of hidden service types and mark their tags
  apply_filters() {
    for (const button of this.filters.children) {
      const shown = !this.hidden.has(button.dataset.key);
      button.setAttribute('aria-pressed', String(shown));
    }
    let visible = 0;
    for (const box of this.boxes.children) {
      box.hidden = this.hidden.has(box.dataset.service);
      visible += box.hidden ? 0 : 1;
    }
    this.all_hidden.hidden = visible > 0 || this.boxes.children.length === 0;
  }

  /// create a service type box
  create_box(type, is_new_box) {
    const box = clone_template('box-template');
    box.dataset.type = type.name;
    box.dataset.service = service_key(type.service);
    if (is_new_box) {
      box.classList.add('new');
    }

    // title row: per service name, accent color and icon
    const appearance = this.service_info.appearance(type.service.service);
    box.style.setProperty('--accent', appearance.color);
    box.style.setProperty('--on-accent', appearance.on_color);
    box.querySelector('.service-icon')
        .appendChild(this.service_info.create_icon(type.service.service));
    box.querySelector('.name').textContent = appearance.name;
    box.querySelector('.service').textContent =
        type.service.service.replace(/^_/, '');
    box.querySelector('.protocol').textContent =
        type.service.protocol.replace(/^_/, '');
    box.querySelector('.count').textContent = type.instances.length;
    box.querySelector('.fqdn').textContent = type.name;

    // remember which instances were already visible
    const previous = this.known.get(type.name);
    const ul = box.querySelector('.entries');
    for (const instance of type.instances) {
      const li = this.create_entry(instance, type.service);
      if (previous && !previous.has(instance.name)) {
        li.classList.add('new');
      }
      ul.appendChild(li);
    }
    if (type.instances.length === 0) {
      const li = document.createElement('li');
      li.className = 'none';
      li.textContent = 'No instances registered';
      ul.appendChild(li);
    }
    this.known.set(type.name, new Set(type.instances.map(i => i.name)));

    return box;
  }

  /// create a service instance entry
  create_entry(instance, service) {
    const li = clone_template('entry-template');
    li.querySelector('.label').textContent = instance.label;
    li.querySelector('.label').title = instance.name;

    // service link, constructed by SdServiceInfo for known services
    const srv = instance.srv[0];
    const service_info = this.service_info;
    const link = srv ? service_info.create_link(
                           service.service, normalize_name(srv.target),
                           srv.port, instance.txt) :
                       null;
    const link_node = li.querySelector('.link');
    if (link) {
      link_node.href = link;
      link_node.querySelector('.url').textContent = link;
      link_node.querySelector('.icon').appendChild(
          service_info.create_icon(service.service));
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

/// clone the first element of a template
function clone_template(id) {
  return document.getElementById(id).content.firstElementChild.cloneNode(true);
}

/// remove trailing dot and surrounding whitespace
function normalize_name(name) {
  return String(name).trim().replace(/\.$/, '');
}

/// the instance part of a service instance name.
/// Instances can live in other zones (e.g. `op6._loc._udp.op6.zenr.io`),
/// so the label is everything in front of the service type labels.
function instance_label(name, service) {
  const marker = '.' + service.service + '.' + service.protocol + '.';
  const index = name.indexOf(marker);
  const label = index > 0 ? name.slice(0, index) : name.split('.')[0];
  // unescape presentation format (`\ ` and `\032`)
  return label.replace(/\\(\d{3})/g, (_, d) => String.fromCharCode(+d))
      .replace(/\\(.)/g, '$1');
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

/// the key a service type is shown or hidden by, e.g. `_http._tcp`
function service_key(service) {
  return service.service + '.' + service.protocol;
}

/// the hidden service types stored in localStorage
function load_hidden() {
  try {
    const stored = JSON.parse(localStorage.getItem(HIDDEN_STORAGE_KEY));
    return new Set(Array.isArray(stored) ? stored : []);
  } catch (error) {
    return new Set();
  }
}

/// store the hidden service types in localStorage
function save_hidden(hidden) {
  try {
    localStorage.setItem(HIDDEN_STORAGE_KEY, JSON.stringify([...hidden]));
  } catch (error) {
    console.warn('could not store hidden service types', error);
  }
}

function unique(array) {
  return [...new Set(array)];
}

function plural(n, word) {
  return n + ' ' + word + (n === 1 ? '' : 's');
}
