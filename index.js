const spawnSync = require('child_process').spawnSync;
const fs = require('fs');
const os = require('os');
const path = require('path');
const process = require('process');

const versionMap = {
  '1': '1.0.0-beta1',
  '1.0': '1.0.0-beta1'
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
  if (!/^[67]\.\d{1,2}\.\d{1,2}(-beta\d)?$/.test(version)) {
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
    url = `TODO`;
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
    run('mv', `opensearch-${opensearchVersion}`, esHome)
  } else {
    fs.renameSync(`opensearch-${opensearchVersion}`, esHome);
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

    let pluginCmd = path.join(esHome, 'bin', 'opensearch-plugin');
    if (isWindows()) {
      pluginCmd += '.bat';
    }
    run(pluginCmd, 'install', '--silent', ...plugins);
  }
}

function startServer() {
  if (isWindows()) {
    const serviceCmd = path.join(esHome, 'bin', 'opensearch-service.bat');
    run(serviceCmd, 'install');
    run(serviceCmd, 'start');
  } else {
    run(path.join(esHome, 'opensearch-tar-install.sh'), '-d', '-E', 'discovery.type=single-node');
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
const esHome = path.join(cacheDir, opensearchVersion);

if (!fs.existsSync(esHome)) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opensearch-'));
  process.chdir(tmpDir);
  download();
  installPlugins();
} else {
  console.log('OpenSearch cached');
}

startServer();

waitForReady();

addToEnv(`ES_HOME=${esHome}`);
addToPath(path.join(esHome, 'bin'));
