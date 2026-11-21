/// DNS-SD Service Information
///
/// Helper class that provides information and helper methods for services.
class SdServiceInfo {
  /// list of service objects
  ///
  /// each service has the following info:
  /// - name: human readable title of the service box
  /// - color: accent color of the service box, the color of the service
  ///   logo or of the logo background. Services without a logo get a
  ///   random color, seeded by the service name so it stays the same.
  /// - icon: the service icon, one of
  ///   - '<name>': Font Awesome solid icon `fa-<name>`
  ///   - 'brands:<name>': Font Awesome brands icon `fa-<name>`
  ///   - 'svg:<name>': embedded SVG icon `SVG_ICONS[<name>]` from icons.js
  /// - url: url protocol start string (e.g.: 'http://'),
  ///   services without url get no link
  /// - default_port: the port that is left out of the link
  /// - txt: TXT entry requirement: 'required', 'optional', 'none'
  service_list = {
    '_http': {
      'name': 'Web',
      'icon': 'globe',
      'url': 'http://',
      'default_port': 80,
      'txt': 'required',
    },
    '_https': {
      'name': 'Web (TLS)',
      'icon': 'globe',
      'url': 'https://',
      'default_port': 443,
      'txt': 'required',
    },
    '_ssh': {
      'name': 'Secure Shell',
      'icon': 'terminal',
      'url': 'ssh://',
      'default_port': 22,
      'txt': 'required',
    },
    '_telnet': {
      'name': 'Telnet',
      'icon': 'keyboard',
      'url': 'telnet://',
      'default_port': 23,
      'txt': 'required',
    },
    '_sftp': {
      'name': 'Secure File Transfer',
      'icon': 'folder-tree',
      'url': 'sftp://',
      'default_port': 22,
      'txt': 'required',
    },
    '_sftp-ssh': {
      'name': 'Secure File Transfer',
      'icon': 'folder-tree',
      'url': 'sftp://',
      'default_port': 22,
      'txt': 'required',
    },
    '_ftp': {
      'name': 'File Transfer',
      'icon': 'file-arrow-down',
      'url': 'ftp://',
      'default_port': 21,
      'txt': 'required',
    },
    '_smb': {
      'name': 'File Shares (SMB)',
      'icon': 'folder-open',
      'url': 'smb://',
      'default_port': 445,
      'txt': 'required',
    },
    '_rfb': {
      'name': 'Remote Desktop (VNC)',
      'icon': 'desktop',
      'url': 'vnc://',
      'default_port': 5900,
      'txt': 'required',
    },
    '_git': {
      'name': 'Git',
      'color': '#f05032',
      'icon': 'brands:git-alt',
      'url': 'git://',
      'default_port': 9418,
      'txt': 'required',
    },
    '_gopher': {
      'name': 'Gopher',
      'icon': 'svg:gopher',
      'url': 'gopher://',
      'default_port': 70,
      'txt': 'required',
    },
    '_ipfs': {
      'name': 'IPFS',
      'color': '#65c2cb',
      'icon': 'svg:ipfs',
    },
    '_qaul': {
      'name': 'qaul',
      'color': '#56a3c8',
      'icon': 'svg:qaul',
    },
    '_wg': {
      'name': 'WireGuard',
      'color': '#88171a',
      'icon': 'svg:wireguard',
    },
    '_wireguard': {
      'name': 'WireGuard',
      'color': '#88171a',
      'icon': 'svg:wireguard',
    },
    '_xmpp': {
      'name': 'XMPP',
      'color': '#002b5c',
      'icon': 'svg:xmpp',
    },
    '_xmpp-client': {
      'name': 'XMPP Chat',
      'color': '#002b5c',
      'icon': 'svg:xmpp',
    },
    '_xmpp-server': {
      'name': 'XMPP Federation',
      'color': '#002b5c',
      'icon': 'svg:xmpp',
    },
    '_ipp': {
      'name': 'Printer',
      'icon': 'print',
      'url': 'ipp://',
      'default_port': 631,
      'txt': 'required',
    },
    '_ipps': {
      'name': 'Printer (TLS)',
      'icon': 'print',
      'url': 'ipps://',
      'default_port': 631,
      'txt': 'required',
    },
    '_loc': {
      'name': 'Location',
      'icon': 'location-dot',
    },
    '_gemini': {
      'name': 'Gemini',
      'icon': 'gem',
      'url': 'gemini://',
      'default_port': 1965,
      'txt': 'required',
    },
  }

  /// look and feel of services that are not in the service list
  unknown_service = {
    'icon': 'circle-nodes',
  }

  /// title, colors and icon of a service, e.g. of '_ssh'.
  /// Unknown services are titled by their name without the leading '_'.
  /// `on_color` is the text color with the better contrast on `color`.
  appearance(service) {
    const service_object = this.service_list[service] || this.unknown_service;
    const rgb = service_object.color ? hex_2_rgb(service_object.color) :
                                       random_color(service);
    return {
      name: service_object.name || service.replace(/^_/, ''),
      color: 'rgb(' + rgb.join(', ') + ')',
      on_color: on_color(rgb),
      icon: service_object.icon,
    };
  }

  /// creates the icon element of a service
  create_icon(service) {
    const icon = this.appearance(service).icon;
    const span = document.createElement('span');
    span.setAttribute('aria-hidden', 'true');
    const [kind, name] = icon.includes(':') ? icon.split(':') : ['solid', icon];
    if (kind === 'svg') {
      span.className = 'svg-icon';
      span.innerHTML = SVG_ICONS[name];
    } else {
      span.className = 'fa-' + kind + ' fa-' + name;
    }
    return span;
  }

  /// creates a service link and returns the link as string
  ///
  /// if the link can't be created, the function returns 'null'
  create_link(service, target, port, txt) {
    let link_user = '';
    let link_port = '';
    let link_path = '';

    // check if service is known and linkable
    let service_object = this.service_list[service];
    if (service_object === undefined || !service_object.url) {
      return null
    }
    let url = service_object.url;
    let default_port = service_object.default_port;
    if (service === '_http' && port === 443) {
      // set specific https settings
      default_port = 443;
      url = 'https://'
    }

    // set port, if it is not at default port
    if (default_port != port) {
      link_port = ':' + port
    }

    // check TXT
    if (txt === null || txt === undefined) {
      if (service_object.txt === 'required') {
        return null
      }
    } else {
      const txt_object = this.txt_2_object(txt)
      if (txt_object.path) {
        link_path = txt_object.path
      }
      if (txt_object.user) {
        link_user = txt_object.user + '@'
      }
    }

    // create link
    let link = url + link_user + target + link_port + link_path;

    return link
  }

  /// Parse binary TXT entries, to get an object of key: value pairs
  txt_2_object(txt_array) {
    let txt_result = {};
    for (let i = 0; i < txt_array.length; i++) {
      for (let j = 0; j < txt_array[i].data.length; j++) {
        // convert the binary array to string
        let entry = String.fromCharCode.apply(String, txt_array[i].data[j])

        // split string
        const key_value = entry.split('=')
        if (key_value.length == 1) {
          txt_result[key_value[0]] = true
        }
        else if (key_value.length == 2) {
          txt_result[key_value[0]] = key_value[1]
        }
        else {
          console.log('unexpected output: ' + key_value);
          txt_result[key_value[0]] = key_value[1]
        }
      }
    }
    return txt_result
  }
}

/// '#rrggbb' to [r, g, b]
function hex_2_rgb(hex) {
  return [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16));
}

/// a random color, seeded by `seed`, so a service always gets the same one
function random_color(seed) {
  // FNV-1a hash of the seed
  let hash = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    hash = Math.imul(hash ^ seed.charCodeAt(i), 0x01000193) >>> 0;
  }
  // mix the bits, so similar short names get well spread hues
  hash ^= hash >>> 16;
  hash = Math.imul(hash, 0x85ebca6b);
  hash ^= hash >>> 13;
  hash = Math.imul(hash, 0xc2b2ae35);
  hash = (hash ^ (hash >>> 16)) >>> 0;
  const hue = hash % 360;
  const saturation = 0.45 + ((hash >>> 9) % 30) / 100;
  const lightness = 0.35 + ((hash >>> 17) % 15) / 100;
  return hsl_2_rgb(hue, saturation, lightness);
}

function hsl_2_rgb(h, s, l) {
  const a = s * Math.min(l, 1 - l);
  const f = n => {
    const k = (n + h / 30) % 12;
    return Math.round(255 * (l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1))));
  };
  return [f(0), f(8), f(4)];
}

/// white or near black, whichever contrasts more with the color [r, g, b]
function on_color(rgb) {
  const [r, g, b] = rgb.map(c => {
    c /= 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  const luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;
  // contrast against white (1.0) vs. against #111111 (~0.0056)
  return (1.05 / (luminance + 0.05)) >= ((luminance + 0.05) / 0.0556) ?
      '#ffffff' :
      '#111111';
}
