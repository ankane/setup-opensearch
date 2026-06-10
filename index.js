const spawnSync = require('child_process').spawnSync;
const fs = require('fs');
const os = require('os');
const path = require('path');
const process = require('process');

const versionMap = {
  '3': '3.7.0',
  '2': '2.19.4',
  '3.7': '3.7.0',
  '3.6': '3.6.0',
  '3.5': '3.5.0',
  '3.4': '3.4.0',
  '3.3': '3.3.2',
  '3.2': '3.2.0',
  '3.1': '3.1.0',
  '3.0': '3.0.0',
  '2.19': '2.19.4',
  '2.18': '2.18.0',
  '2.17': '2.17.1',
  '2.16': '2.16.0',
  '2.15': '2.15.0',
  '2.14': '2.14.0',
  '2.13': '2.13.0',
  '2.12': '2.12.0',
  '2.11': '2.11.1',
  '2.10': '2.10.0',
  '2.9': '2.9.0',
  '2.8': '2.8.0',
  '2.7': '2.7.0',
  '2.6': '2.6.0',
  '2.5': '2.5.0',
  '2.4': '2.4.1',
  '2.3': '2.3.0',
  '2.2': '2.2.1',
  '2.1': '2.1.0',
  '2.0': '2.0.1'
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

// only use with validated input
// https://github.com/nodejs/node/issues/52554
function runBat() {
  const args = Array.from(arguments);
  console.log(args.join(' '));
  const command = args.shift();
  if (!fs.existsSync(command)) {
    throw 'Bat not found';
  }
  const ret = spawnSync(command, args, {stdio: 'inherit', shell: true});
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
  let version = process.env['INPUT_OPENSEARCH-VERSION'] || (isWindows() ? '2' : '3');
  if (versionMap[version]) {
    version = versionMap[version];
  }
  if (!/^[32]\.\d{1,2}\.\d{1,2}$/.test(version)) {
    throw `OpenSearch version not supported: ${version}`;
  }
  const majorVersion = parseInt(version);
  const minorVersion = parseInt(version.split('.')[1]);
  if (isWindows() && (majorVersion == 2 && minorVersion < 4)) {
    throw `OpenSearch version not supported on Windows (requires 2.4+)`;
  }
  return version;
}

function isWindows() {
  return process.platform == 'win32';
}

function getUrl() {
  let arch = process.arch;
  if (!['x64', 'arm64'].includes(arch)) {
    throw `Unsupported architecture: ${arch}`;
  }

  let url;
  if (process.platform == 'darwin') {
    // TODO use Mac build when available
    // https://github.com/opensearch-project/opensearch-build/issues/38
    url = `https://artifacts.opensearch.org/releases/bundle/opensearch/${opensearchVersion}/opensearch-${opensearchVersion}-linux-${arch}.tar.gz`;
  } else if (isWindows()) {
    url = `https://artifacts.opensearch.org/releases/bundle/opensearch/${opensearchVersion}/opensearch-${opensearchVersion}-windows-x64.zip`;
  } else {
    url = `https://artifacts.opensearch.org/releases/bundle/opensearch/${opensearchVersion}/opensearch-${opensearchVersion}-linux-${arch}.tar.gz`;
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

function installPlugins() {
  let plugins = (process.env['INPUT_PLUGINS'] || '').trim();
  if (plugins.length > 0) {
    console.log('Installing plugins');

    // split here instead of above since JS returns [''] for empty array
    plugins = plugins.split(/\s*[,\n]\s*/);

    // validate
    // do not change without checking impact on runBat
    plugins.forEach( function(plugin) {
      if (!/^\w(\w|-)+$/.test(plugin)) {
        throw `Invalid plugin: ${plugin}`;
      }
    });

    let pluginCmd = path.join(opensearchHome, 'bin', 'opensearch-plugin');
    let runCmd = run;
    if (isWindows()) {
      pluginCmd += '.bat';
      runCmd = runBat;
    }
    runCmd(pluginCmd, 'install', '--silent', '--batch', ...plugins);
  }
}

function setConfig(dir) {
  let config = process.env['INPUT_CONFIG'] || '';
  config += '\n';
  config += 'plugins.security.disabled: true\n';
  config += 'discovery.type: single-node\n';

  const file = path.join(dir, 'config', 'opensearch.yml');
  // overwrite instead of append to play nicely with caching
  // alternatively, could append to copy of original file
  fs.writeFileSync(file, config);
}

function startServer() {
  if (isWindows()) {
    const serviceCmd = path.join(opensearchHome, 'bin', 'opensearch-service.bat');
    runBat(serviceCmd, 'install');
    runBat(serviceCmd, 'start');
  } else {
    run(path.join(opensearchHome, 'bin', 'opensearch'), '-d');
  }
}

function getPort() {
  const config = process.env['INPUT_CONFIG'] || '';
  const match = config.match(/\bhttp\.port: +(\d{4,5})\b/);
  return match ? parseInt(match[1]) : 9200;
}

function waitForReady() {
  console.log("Waiting for server to be ready");
  for (let i = 0; i < 30; i++) {
    let ret = spawnSync('curl', ['-s', `localhost:${getPort()}`]);
    if (ret.status === 0) {
      break;
    }
    spawnSync('sleep', ['1']);
  }
}

const opensearchVersion = getVersion();
const cacheDir = path.join(os.homedir(), 'opensearch');
const opensearchHome = path.join(cacheDir, opensearchVersion);

// java compatibility
// https://opensearch.org/docs/latest/opensearch/install/compatibility/
const javaHome = parseInt(opensearchVersion) == 3 ? process.env.JAVA_HOME_21_X64 : process.env.JAVA_HOME_11_X64;

// not set on ubuntu-22.04, but defaults to Java 17
if (javaHome) {
  process.env.OPENSEARCH_JAVA_HOME = javaHome;
  addToEnv(`OPENSEARCH_JAVA_HOME=${javaHome}`);

  if (isWindows()) {
    process.env.JAVA_HOME = javaHome;
  }
}

if (!fs.existsSync(opensearchHome)) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opensearch-'));
  process.chdir(tmpDir);
  download();
  installPlugins();
} else {
  console.log('OpenSearch cached');
}

setConfig(opensearchHome);
startServer();

waitForReady();

addToEnv(`OPENSEARCH_HOME=${opensearchHome}`);
addToPath(path.join(opensearchHome, 'bin'));
