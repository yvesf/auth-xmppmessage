///! Prints logging similar to apache http access.log
use std::net::IpAddr;
use conduit::{Request, Response};
use time;

pub struct LogEntry {
    remote_ip_address: IpAddr,
    remote_user: String,
    request_path: String,
    time: time::Tm,
    status: u32,
    response_size: u32,
}

impl LogEntry {
    pub fn start(req: &Request) -> LogEntry {
        let entry = LogEntry {
            remote_ip_address: req.remote_addr().ip(),
            remote_user: String::new(),
            request_path: String::from(req.path()),
            time: time::now(),
            status: 0,
            response_size: 0,
        };
        return entry
    }

    pub fn done(&mut self, response: Response) ->  Response {
        let (status_code, _) = response.status;
        self.status = status_code;
        self.print();
        return response;
    }

    #[inline(always)]
    fn print(&self) {
        println!("{} - {} - [{}] \"{}\" {} {}",
                 self.remote_ip_address,
                 self.remote_user,
                 time::strftime("%d/%b/%Y %T %z", &self.time).unwrap(),
                 self.request_path,
                 self.status,
                 self.response_size);
    }
}
