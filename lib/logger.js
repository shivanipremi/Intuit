const winston = require('winston');
const os = require('os');
const path = require('path');
const fs = require('fs');
const cluster = require('cluster');
const moment = require('moment');

// Setup winston by default to the console.
winston.configure({
    exitOnError: false,
    format: winston.format.combine(
        winston.format(info => {
            // Add metadata to the log message
            info.hostname = os.hostname();
            return info;
        })(),
        winston.format.timestamp({
            format: () => moment().format('YYYY-MM-DD HH:mm:ss.SSS')
        }),
        // Use colors only when output supports TTY
        process.stdout.isTTY ? winston.format.colorize() : winston.format.uncolorize(),
        winston.format.printf(({ level, message, timestamp }) => {
            return `${timestamp} ${level}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console({
            handleExceptions: true,
            humanReadableUnhandledException: true
        })
    ]
});

function isDebugEnabled() {
    let l = this.level + '';
    return l.toLowerCase() === 'debug';
}

winston.isDebugEnabled = isDebugEnabled;

/**
 * Call this method to reinitialize winston and add file based logging as needed.
 * Option object has the following properties: <br>
 * @param {Object} options
 * @param {Number} options.port        - mandatory when processNr greater than 1<br>
 * @param {String} options.appName     - name of application, will be used to created directory and file name
 * @param {boolean} options.logToFile  - deprecated true/false (default is false)
 * @param {boolean} options.noDir      - deprecated, when set to true, do not create subdirectory in ./logs. <br>
 * @param {string} options.console     - console type, one of text, json
 * @param {string} options.logLevel    - one of debug/info/warn/error/fatal/none, default is info
 * @param {boolean} options.debug      - when set enable debug level, default false
 * @param {boolean} options.exitOnError- when set, exit node.js process on uncaught errors
 * @param {boolean} options.noRewriters - when set skip recording pid/hostname/appName
 * @return {Winston}
 */
function initLog(options) {
    const appName = options.appName || path.basename(process.argv[1], '.js');
    const hostname = os.hostname();
    const sysRoot = path.join(__dirname, '..');
    const logRoot = path.join(sysRoot, 'logs');

    function prepareDir(dir) {
        try {
            fs.mkdirSync(dir);
        } catch (err) {
            if (err.code === 'EEXIST') return;
            console.log(`error: ${JSON.stringify(err)}`, err);
            throw err;
        }
    }

    let logFile = '';

    function prepareLog() {
        if (!cluster.isMaster) {
            // if this is a child process, include pid in the name to avoid race condition logging to file
            logFile = `${appName}-${hostname}-${process.pid}.log`;
        } else {
            logFile = `${appName}-${hostname}.log`;
        }
        prepareDir(logRoot);
        if (options.noDir) {
            logFile = path.join(logRoot, logFile);
        } else {
            let logDir = path.join(logRoot, appName);
            prepareDir(logDir);
            logFile = path.join(logDir, logFile);
        }
    }

    const useConsole = options.console && options.console.toLowerCase() !== 'none';
    const useJson = !options.console || options.console.toLowerCase() === 'json';

    winston.configure({
        exitOnError: options.exitOnError || false,
        transports: [
            new winston.transports.Console({
                format: winston.format.combine(
                    winston.format(info => {
                        // Add metadata to the log message
                        info.hostname = os.hostname();
                        return info;
                    })(),
                    winston.format.timestamp({
                        format: () => moment().format('YYYY-MM-DD HH:mm:ss.SSS')
                    }),
                    process.stdout.isTTY ? winston.format.colorize() : winston.format.uncolorize(),
                    winston.format.printf(({ level, message, timestamp }) => {
                        return `${timestamp} ${level}: ${message}`;
                    })
                ),
                json: useJson,
                handleExceptions: true,
                humanReadableUnhandledException: true
            })
        ]
    });

    const LOG_LEVELS = ['debug', 'info', 'warn', 'error', 'fatal', 'none'];
    const level = (options.logLevel || '').trim().toLowerCase();
    const mappedLevel = LOG_LEVELS.find(l => l === level);
    winston.level = options.debug ? 'debug' : (mappedLevel || 'info');

    if (options.logToFile) {
        prepareLog();
        winston.add(new winston.transports.File({
            filename: logFile,
            localTime: true,
            timestamp: true,
            handleExceptions: true,
            humanReadableUnhandledException: true
        }));
        if (!useConsole) {
            winston.remove(winston.transports.Console);
        }
    }

    winston.isDebugEnabled = isDebugEnabled;
    return winston;
}

winston.initLog = initLog;

module.exports = winston;
