function startup(lib, off, path) {
  let base = Module.findBaseAddress(lib);

  if (base == null) {
    Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
      onEnter(args) {
        const opened = args[0].readCString();

        if (opened == lib) {
          base = Module.findBaseAddress(lib);

          if (base != null) {
            const target = base.add(off);
            memdump(target, path);
          }
        }
      },
    })
  }
  else {
    const target = base.add(off);
    memdump(target, path);
  }
}

function memdump(addr, path) {
  let once = false;

  Interceptor.attach(addr, {
    onEnter() {
      if (once) return;
      once = true;

      const modules = Process.enumerateRanges('r--');
      const data = JSON.stringify(modules, null, 2);
      writeFile(`${path}/modules.json`, data);


      for (const m of modules) {
        try {
          const data = m.base.readByteArray(m.size);
          writeFile(`${path}/${m.base.toString(16)}.bin`, data);
        } catch (ex) {
          console.log(ex);
        }
      }
    }
  })
}

function writeFile(path, data) {
  console.log(`write dump data to ${path}`);
  const file = new File(path, 'wb');
  file.write(data);
  file.close();
}

rpc.exports = {
  init(stage, params) {
    startup(params.lib, params.off, params.path);
  }
}
