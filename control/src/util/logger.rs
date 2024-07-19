use log::LevelFilter;
use log4rs::{
    append::file::FileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use std::env;

// Logger builder
pub fn build_logger() {
    // Initialize logger.
    let log_path = match env::var("OUTREC_LOG_PATH") {
        Ok(path) => path,
        Err(_) => "./log/output.log".to_string(),
    };
    // Define log level.
    let log_level = match env::var("OUTREC_LOG_LEVEL") {
        Ok(level) => match level.to_lowercase().as_str() {
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info,
        },
        Err(_) => LevelFilter::Error,
    };
    // Create log file.
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{l}:{d} - {m}\n")))
        .build(log_path)
        .expect("Unable to create log file");
    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(log_level))
        .expect("Unable to create logger");
    log4rs::init_config(config).expect("Unable to initialize logger");
}
