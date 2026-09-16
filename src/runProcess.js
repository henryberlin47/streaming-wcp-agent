import { spawn } from 'node:child_process';

/**
 * Run a command, streaming stdout/stderr line-by-line into the job log.
 *
 * @param {object} opts
 * @param {string} opts.command            executable (e.g. 'bash')
 * @param {string[]} opts.args             arguments (passed as an array — no shell,
 *                                          so no injection from interpolated values)
 * @param {object} [opts.env]              extra env vars
 * @param {string} [opts.cwd]              working dir
 * @param {string} [opts.stdin]            data to write to stdin then close (for
 *                                          feeding non-interactive answers)
 * @param {object} helpers                 { log, err, onCancel } from the job runner
 * @returns {Promise<{code:number}>}       resolves on exit 0, rejects otherwise
 */
export function runProcess(opts, helpers) {
  const { command, args = [], env = {}, cwd, stdin } = opts;
  const { log, err, onCancel } = helpers;

  return new Promise((resolve, reject) => {
    log(`$ ${command} ${args.join(' ')}`);

    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      // Never a shell: args are passed literally.
      shell: false,
    });

    // Register a cancel hook: SIGTERM, then SIGKILL after a grace period.
    let killed = false;
    onCancel?.((reason) => {
      killed = true;
      err(`[cancel:${reason}] sending SIGTERM to pid ${child.pid}`);
      try {
        child.kill('SIGTERM');
      } catch {}
      setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {}
      }, 5000).unref?.();
    });

    // Line-buffer both streams so log entries are clean lines.
    attachLineReader(child.stdout, (line) => log(line));
    attachLineReader(child.stderr, (line) => err(line));

    if (stdin != null) {
      child.stdin.write(stdin);
    }
    child.stdin.end();

    child.on('error', (e) => {
      reject(new Error(`spawn failed: ${e.message}`));
    });

    child.on('close', (code, signal) => {
      if (killed) {
        return reject(new Error(`process cancelled (signal ${signal || 'n/a'})`));
      }
      if (code === 0) {
        resolve({ code: 0 });
      } else {
        reject(new Error(`exited with code ${code}${signal ? ` (signal ${signal})` : ''}`));
      }
    });
  });
}

// Emit complete lines as they arrive; flush partial trailing line on end.
function attachLineReader(stream, onLine) {
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).replace(/\r$/, '');
      buf = buf.slice(idx + 1);
      onLine(line);
    }
  });
  stream.on('end', () => {
    if (buf.length) onLine(buf.replace(/\r$/, ''));
  });
}