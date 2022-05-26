const spawnSync = require('child_process').spawnSync;
const fs = require('fs');
const os = require('os');
const path = require('path');
const process = require('process');

const versionMap = {
  '2': '2.0.0',
  '1': '1.3.2',
  '2.0': '2.0.0',
  '1.3': '1.3.2',
  '1.2': '1.2.4',
  '1.1': '1.1.0',
  '1.0': '1.0.1'
};

function run() {
  const args = Array.from(arguments);
  console.log(args.join(' '));
  const command = args.shift();
  // spawn is safer and more lightweight than exec
  const ret = spawnSync(command, args, {stdio: 'inherit'});
  if (ret.status !== 0) {
    throw ret.error;
  }
}

function addToEnv(value) {
  fs.appendFileSync(process.env.GITHUB_ENV, `${value}\n`);
}

function addToPath(value) {
  fs.appendFileSync(process.env.GITHUB_PATH, `${value}\n`);
}

function getVersion() {
  let version = process.env['INPUT_OPENSEARCH-VERSION'] || '1';
  if (versionMap[version]) {
    version = versionMap[version];
  }
  if (!/^[21]\.\d{1,2}\.\d{1,2}$/.test(version)) {
    throw `OpenSearch version not supported: ${version}`;
  }
  return version;
}

function isWindows() {
  return process.platform == 'win32';
}

function getUrl() {
  let url;
  if (process.platform == 'darwin') {
    // TODO use Mac build when available
    // https://github.com/opensearch-project/opensearch-build/issues/38
    url = `https://artifacts.opensearch.org/releases/bundle/opensearch/${opensearchVersion}/opensearch-${opensearchVersion}-linux-x64.tar.gz`;
  } else if (isWindows()) {
    url = `TODO`;
  } else {
    url = `https://artifacts.opensearch.org/releases/bundle/opensearch/${opensearchVersion}/opensearch-${opensearchVersion}-linux-x64.tar.gz`;
  }
  return url;
}

function download() {
  const url = getUrl();
  if (isWindows()) {
    run('curl', '-s', '-o', 'opensearch.zip', url);
    run('unzip', '-q', 'opensearch.zip');
  } else {
    run('wget', '-q', '-O', 'opensearch.tar.gz', url);
    run('tar', 'xfz', 'opensearch.tar.gz');
  }
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, {recursive: true});
  }
  if (isWindows()) {
    // fix for: cross-device link not permitted
    run('mv', `opensearch-${opensearchVersion}`, opensearchHome)
  } else {
    fs.renameSync(`opensearch-${opensearchVersion}`, opensearchHome);
  }
}

// log4j
function fixLog4j() {
  // string comparison not ideal, but works for current versions
  if (opensearchVersion >= '1.2.2') {
    return;
  }

  const jvmOptionsPath = path.join(opensearchHome, 'config', 'jvm.options');
  if (!fs.readFileSync(jvmOptionsPath).includes('log4j2.formatMsgNoLookups')) {
    fs.appendFileSync(jvmOptionsPath, '\n-Dlog4j2.formatMsgNoLookups=true\n');

    // remove jndi for extra safety
    const coreJarPath = fs.readdirSync(path.join(opensearchHome, 'lib')).filter(fn => fn.includes('log4j-core-'))[0];
    run('zip', '-q', '-d', path.join(opensearchHome, 'lib', coreJarPath), 'org/apache/logging/log4j/core/lookup/JndiLookup.class');
  }
}

function installPlugins() {
  let plugins = (process.env['INPUT_PLUGINS'] || '').trim();
  if (plugins.length > 0) {
    console.log('Installing plugins');

    // split here instead of above since JS returns [''] for empty array
    plugins = plugins.split(/\s*[,\n]\s*/);

    // validate
    plugins.forEach( function(plugin) {
      if (!/^[a-zA-Z0-9-]+$/.test(plugin)) {
        throw `Invalid plugin: ${plugin}`;
      }
    });

    let pluginCmd = path.join(opensearchHome, 'bin', 'opensearch-plugin');
    if (isWindows()) {
      pluginCmd += '.bat';
    }
    run(pluginCmd, 'install', '--silent', ...plugins);
  }
}

function startServer() {
  if (isWindows()) {
    const serviceCmd = path.join(opensearchHome, 'bin', 'opensearch-service.bat');
    run(serviceCmd, 'install');
    run(serviceCmd, 'start');
  } else {
    process.env.OPENSEARCH_JAVA_HOME = process.env.JAVA_HOME_17_X64;
    run(path.join(opensearchHome, 'bin', 'opensearch'), '-d', '-E', 'plugins.security.disabled=true', '-E', 'discovery.type=single-node');
  }
}

function waitForReady() {
  console.log("Waiting for server to be ready");
  for (let i = 0; i < 30; i++) {
    let ret = spawnSync('curl', ['-s', 'localhost:9200']);
    if (ret.status === 0) {
      break;
    }
    spawnSync('sleep', ['1']);
  }
}

const opensearchVersion = getVersion();
const cacheDir = path.join(os.homedir(), 'opensearch');
const opensearchHome = path.join(cacheDir, opensearchVersion);

if (!fs.existsSync(opensearchHome)) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opensearch-'));
  process.chdir(tmpDir);
  download();
  fixLog4j();
  installPlugins();
} else {
  console.log('OpenSearch cached');
  fixLog4j();
}

startServer();

waitForReady();

addToEnv(`OPENSEARCH_HOME=${opensearchHome}`);
addToPath(path.join(opensearchHome, 'bin'));
