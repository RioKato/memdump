function startup(lib, off) {
  let base = Module.findBaseAddress(lib);

  if (!base) {
    Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
      onEnter(args) {
        const opened = args[0].readCString();

        if (opened == lib) {
          base = Module.findBaseAddress(lib);
          const target = base.add(off);
          memdump(target);
        }
      },
    })
  }
  else {
    const target = base.add(off);
    memdump(target);
  }
}

function memdump(addr) {
  Interceptor.attach(addr, {
    onEnter() {
      const modules = Process.enumerateRanges('r--');
      const data = JSON.stringify(modules, null, 2);
      writeFile('modules.json', data);


      for (const m of modules) {
        try {
          const data = m.base.readByteArray(m.size);
          writeFile(`${m.base.toString(16)}.bin`, data);
        } catch (ex) {
          console.log(ex);
        }
      }
    }
  })
}

function writeFile(path, data) {
  const file = new File(path, 'wb');
  file.write(data);
  file.close();
}
