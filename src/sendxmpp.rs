///! Interface for the C implementation oof sending xmpp message

use std::ffi::{CString, NulError};
use std::os::raw::c_char;

pub fn send_message(jid: &str, password: &str, message: &str, to: &str) -> Result<(), NulError> {
    extern {
        pub fn send_message(jid: *const c_char,
                            password: *const c_char,
                            message: *const c_char,
                            to: *const c_char);
    }
    let cjid = try!(CString::new(jid));
    let cpassword = try!(CString::new(password));
    let cmessage = try!(CString::new(message));
    let cto = try!(CString::new(to));
    unsafe {
        send_message(cjid.as_ptr(), cpassword.as_ptr(), cmessage.as_ptr(), cto.as_ptr());
    }
    Ok(())
}