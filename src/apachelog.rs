///! Prints logging similar to apache http access.log
use std::net::IpAddr;
use std::io::Read;

use time;
use tiny_http::{Request, Response};

pub struct LogEntry {
    remote_ip_address: IpAddr,
    remote_user: String,
    request_path: String,
    time: time::Tm,
    status: u16,
    response_size: u32,
}

impl LogEntry {
    pub fn start(req: &Request) -> LogEntry {
        let entry = LogEntry {
            remote_ip_address: req.remote_addr().ip(),
            remote_user: String::new(),
            request_path: String::from(req.url()),
            time: time::now(),
            status: 0,
            response_size: 0,
        };
        return entry
    }

    pub fn done<R>(&mut self, _: &Response<R>, status_code: u16) where R: Read {
        self.status = status_code; // request.statuscode is not accessible :(
        self.print();
    }

    #[inline(always)]
    fn print(&self) {
        info!("{} - {} - [{}] \"{}\" {} {}",
              self.remote_ip_address,
              self.remote_user,
              time::strftime("%d/%b/%Y %T %z", &self.time).unwrap(),
              self.request_path,
              self.status,
              self.response_size);
    }
}
