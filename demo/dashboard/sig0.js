/// sig0lease WASM loader
///
/// Loads `sig0lease-web.wasm.gz` (cmd/sig0lease-web, built by `make web`
/// into bin/web together with Go's matching `wasm_exec.js`), unzips it in
/// the browser, runs it, which sets the global `sig0lease` object, and then
/// dispatches the `wasm_ready` event.

(async () => {
  try {
    const go = new Go();
    const resp = await fetch('sig0lease-web.wasm.gz');
    if (!resp.ok) {
      throw new Error(
          'sig0lease-web.wasm.gz: ' + resp.status + ' ' + resp.statusText);
    }
    const wasm = await new Response(
        resp.body.pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
    const {instance} = await WebAssembly.instantiate(wasm, go.importObject);
    go.run(instance);  // sets the global sig0lease, then waits for calls

    window.dispatchEvent(new CustomEvent('wasm_ready'));
  } catch (error) {
    console.error('WASM did not load', error);
    window.dispatchEvent(new CustomEvent('wasm_failed', {detail: error}));
  }
})();
