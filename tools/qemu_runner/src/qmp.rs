use std::collections::VecDeque;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

#[derive(Debug)]
pub enum QmpError {
    Io {
        operation: &'static str,
        source: std::io::Error,
    },
    Json {
        operation: &'static str,
        source: serde_json::Error,
    },
    Protocol {
        operation: &'static str,
        detail: Box<str>,
    },
    Command {
        execute: Box<str>,
        class: Box<str>,
        description: Box<str>,
    },
    TimedOut {
        operation: &'static str,
    },
    HotpluggableCpuIndexOutOfRange {
        requested: usize,
        available: usize,
    },
}

impl fmt::Display for QmpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "QMP {operation} failed: {source}"),
            Self::Json { operation, source } => {
                write!(formatter, "QMP {operation} returned invalid JSON: {source}")
            }
            Self::Protocol { operation, detail } => {
                write!(formatter, "QMP {operation} violated the protocol: {detail}")
            }
            Self::Command {
                execute,
                class,
                description,
            } => write!(
                formatter,
                "QMP command '{execute}' failed ({class}): {description}"
            ),
            Self::TimedOut { operation } => write!(formatter, "QMP {operation} timed out"),
            Self::HotpluggableCpuIndexOutOfRange {
                requested,
                available,
            } => write!(
                formatter,
                "QMP hotpluggable CPU index {requested} is outside the {available} available slots"
            ),
        }
    }
}

impl std::error::Error for QmpError {}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct HotpluggableCpu {
    driver: Box<str>,
    properties: Map<String, Value>,
    qom_path: Option<Box<str>>,
}

impl HotpluggableCpu {
    fn decode(value: Value) -> Result<Self, QmpError> {
        let object = value.as_object().ok_or_else(|| QmpError::Protocol {
            operation: "query-hotpluggable-cpus",
            detail: String::from("array entry is not an object").into_boxed_str(),
        })?;
        let driver =
            object
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| QmpError::Protocol {
                    operation: "query-hotpluggable-cpus",
                    detail: String::from("CPU entry has no string 'type'").into_boxed_str(),
                })?;
        let properties = object
            .get("props")
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| QmpError::Protocol {
                operation: "query-hotpluggable-cpus",
                detail: String::from("CPU entry has no object 'props'").into_boxed_str(),
            })?;
        Ok(Self {
            driver: Box::from(driver),
            properties,
            qom_path: object
                .get("qom-path")
                .and_then(Value::as_str)
                .map(Box::from),
        })
    }

    fn topology_key(&self) -> Result<[u64; 6], QmpError> {
        const COORDINATES: [&str; 6] = [
            "socket-id",
            "die-id",
            "cluster-id",
            "module-id",
            "core-id",
            "thread-id",
        ];
        let mut key = [0u64; COORDINATES.len()];
        for (index, coordinate) in COORDINATES.iter().enumerate() {
            let Some(value) = self.properties.get(*coordinate) else {
                continue;
            };
            key[index] = value.as_u64().ok_or_else(|| QmpError::Protocol {
                operation: "query-hotpluggable-cpus",
                detail: format!("CPU topology property '{coordinate}' is not an unsigned integer")
                    .into_boxed_str(),
            })?;
        }
        Ok(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HotpluggedCpu {
    pub(super) device_id: Box<str>,
    qom_path: Box<str>,
    driver: Box<str>,
    properties: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DeviceDeleteOutcome {
    Deleted,
    GuestRejected {
        device: Option<Box<str>>,
        path: Option<Box<str>>,
        acpi_status: Option<u64>,
    },
}

pub(super) struct QmpClient {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    events: VecDeque<Value>,
    next_command_id: u64,
}

impl QmpClient {
    pub(super) fn connect(address: SocketAddr, deadline: Instant) -> Result<Self, QmpError> {
        let stream = loop {
            match TcpStream::connect_timeout(&address, Duration::from_millis(200)) {
                Ok(stream) => break stream,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => {
                    return Err(QmpError::Io {
                        operation: "connect",
                        source: error,
                    });
                }
            }
        };
        stream.set_nodelay(true).map_err(|source| QmpError::Io {
            operation: "configure transport",
            source,
        })?;
        let writer = stream.try_clone().map_err(|source| QmpError::Io {
            operation: "clone transport",
            source,
        })?;
        let mut client = Self {
            reader: BufReader::new(stream),
            writer,
            events: VecDeque::new(),
            next_command_id: 1,
        };

        let greeting = client.read_message(deadline, "greeting")?;
        if !greeting.get("QMP").is_some_and(Value::is_object) {
            return Err(QmpError::Protocol {
                operation: "greeting",
                detail: String::from("message has no QMP greeting object").into_boxed_str(),
            });
        }
        client.execute("qmp_capabilities", Map::new(), deadline)?;
        Ok(client)
    }

    pub(super) fn query_hotpluggable_cpus(
        &mut self,
        deadline: Instant,
    ) -> Result<Vec<HotpluggableCpu>, QmpError> {
        let response = self.execute("query-hotpluggable-cpus", Map::new(), deadline)?;
        let entries = response.as_array().ok_or_else(|| QmpError::Protocol {
            operation: "query-hotpluggable-cpus",
            detail: String::from("return value is not an array").into_boxed_str(),
        })?;
        entries
            .iter()
            .cloned()
            .map(HotpluggableCpu::decode)
            .collect()
    }

    pub(super) fn add_available_cpu(
        &mut self,
        device_id: &str,
        available_index: usize,
        deadline: Instant,
    ) -> Result<HotpluggedCpu, QmpError> {
        let mut available = Vec::new();
        for slot in self
            .query_hotpluggable_cpus(deadline)?
            .into_iter()
            .filter(|slot| slot.qom_path.is_none())
        {
            available.push((slot.topology_key()?, slot));
        }
        available.sort_by_key(|(key, _)| *key);
        let available_count = available.len();
        let (_, slot) = available.into_iter().nth(available_index).ok_or(
            QmpError::HotpluggableCpuIndexOutOfRange {
                requested: available_index,
                available: available_count,
            },
        )?;
        self.add_cpu_slot(slot, device_id, deadline)
    }

    pub(super) fn readd_cpu(
        &mut self,
        prior: &HotpluggedCpu,
        device_id: &str,
        deadline: Instant,
    ) -> Result<HotpluggedCpu, QmpError> {
        self.add_cpu_slot(
            HotpluggableCpu {
                driver: prior.driver.clone(),
                properties: prior.properties.clone(),
                qom_path: None,
            },
            device_id,
            deadline,
        )
    }

    fn add_cpu_slot(
        &mut self,
        slot: HotpluggableCpu,
        device_id: &str,
        deadline: Instant,
    ) -> Result<HotpluggedCpu, QmpError> {
        let driver = slot.driver;
        let properties = slot.properties;
        let mut arguments = properties.clone();
        arguments.insert("driver".into(), Value::String(driver.to_string()));
        arguments.insert("id".into(), Value::String(device_id.into()));
        self.execute("device_add", arguments, deadline)?;
        let qom_path = self
            .query_hotpluggable_cpus(deadline)?
            .into_iter()
            .find(|slot| {
                slot.driver == driver && slot.properties == properties && slot.qom_path.is_some()
            })
            .and_then(|slot| slot.qom_path)
            .ok_or_else(|| QmpError::Protocol {
                operation: "device_add",
                detail: String::from("added CPU slot has no occupied QOM path").into_boxed_str(),
            })?;
        Ok(HotpluggedCpu {
            device_id: Box::from(device_id),
            qom_path,
            driver,
            properties,
        })
    }

    pub(super) fn request_cpu_delete(
        &mut self,
        cpu: &HotpluggedCpu,
        deadline: Instant,
    ) -> Result<(), QmpError> {
        let mut arguments = Map::new();
        arguments.insert("id".into(), Value::String(cpu.device_id.to_string()));
        self.execute("device_del", arguments, deadline)?;
        Ok(())
    }

    pub(super) fn wait_for_device_delete_outcome(
        &mut self,
        cpu: &HotpluggedCpu,
        deadline: Instant,
    ) -> Result<DeviceDeleteOutcome, QmpError> {
        loop {
            let event = match self.events.pop_front() {
                Some(event) => event,
                None => self.read_message(deadline, "wait for CPU delete outcome")?,
            };
            match event.get("event").and_then(Value::as_str) {
                Some("DEVICE_UNPLUG_GUEST_ERROR") if event_matches_cpu(&event, cpu) => {
                    let data = event.get("data").and_then(Value::as_object);
                    return Ok(DeviceDeleteOutcome::GuestRejected {
                        device: data
                            .and_then(|data| data.get("device"))
                            .and_then(Value::as_str)
                            .map(Box::from),
                        path: data
                            .and_then(|data| data.get("path"))
                            .and_then(Value::as_str)
                            .map(Box::from),
                        acpi_status: None,
                    });
                }
                Some("ACPI_DEVICE_OST") => {
                    eprintln!("QMP observed ACPI_DEVICE_OST: {event}");
                    if let Some(outcome) = acpi_ost_delete_outcome(&event, cpu)? {
                        return Ok(outcome);
                    }
                }
                Some("DEVICE_DELETED") if event_matches_cpu(&event, cpu) => {
                    return Ok(DeviceDeleteOutcome::Deleted);
                }
                _ => {}
            }
        }
    }

    fn execute(
        &mut self,
        execute: &str,
        arguments: Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, QmpError> {
        let command_id = self.next_command_id;
        self.next_command_id =
            self.next_command_id
                .checked_add(1)
                .ok_or_else(|| QmpError::Protocol {
                    operation: "allocate command id",
                    detail: String::from("command identifier space exhausted").into_boxed_str(),
                })?;
        let command = json!({
            "execute": execute,
            "arguments": arguments,
            "id": command_id,
        });
        serde_json::to_writer(&mut self.writer, &command).map_err(|source| QmpError::Json {
            operation: "encode command",
            source,
        })?;
        self.writer
            .write_all(b"\r\n")
            .map_err(|source| QmpError::Io {
                operation: "write command delimiter",
                source,
            })?;
        self.writer.flush().map_err(|source| QmpError::Io {
            operation: "flush command",
            source,
        })?;

        loop {
            let response = self.read_message(deadline, "command response")?;
            if response.get("event").is_some() {
                self.events.push_back(response);
                continue;
            }
            if response.get("id").and_then(Value::as_u64) != Some(command_id) {
                return Err(QmpError::Protocol {
                    operation: "command response",
                    detail: format!("unexpected response id for '{execute}'").into_boxed_str(),
                });
            }
            if let Some(error) = response.get("error").and_then(Value::as_object) {
                return Err(QmpError::Command {
                    execute: Box::from(execute),
                    class: error
                        .get("class")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown")
                        .into(),
                    description: error
                        .get("desc")
                        .and_then(Value::as_str)
                        .unwrap_or("QMP command failed without a description")
                        .into(),
                });
            }
            return response
                .get("return")
                .cloned()
                .ok_or_else(|| QmpError::Protocol {
                    operation: "command response",
                    detail: format!("'{execute}' response has neither return nor error")
                        .into_boxed_str(),
                });
        }
    }

    fn read_message(
        &mut self,
        deadline: Instant,
        operation: &'static str,
    ) -> Result<Value, QmpError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(QmpError::TimedOut { operation })?;
        self.reader
            .get_mut()
            .set_read_timeout(Some(remaining))
            .map_err(|source| QmpError::Io { operation, source })?;
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err(QmpError::Protocol {
                operation,
                detail: String::from("transport closed before a complete message").into_boxed_str(),
            }),
            Ok(_) => {
                serde_json::from_str(&line).map_err(|source| QmpError::Json { operation, source })
            }
            Err(source)
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Err(QmpError::TimedOut { operation })
            }
            Err(source) => Err(QmpError::Io { operation, source }),
        }
    }
}

fn acpi_ost_delete_outcome(
    event: &Value,
    cpu: &HotpluggedCpu,
) -> Result<Option<DeviceDeleteOutcome>, QmpError> {
    let Some(data) = event.get("data").and_then(Value::as_object) else {
        return Err(QmpError::Protocol {
            operation: "ACPI_DEVICE_OST",
            detail: String::from("event has no object data").into_boxed_str(),
        });
    };
    let info = data
        .get("info")
        .and_then(Value::as_object)
        .ok_or_else(|| QmpError::Protocol {
            operation: "ACPI_DEVICE_OST",
            detail: String::from("event data has no object info").into_boxed_str(),
        })?;
    if info.get("device").and_then(Value::as_str) != Some(cpu.device_id.as_ref()) {
        return Ok(None);
    }

    let source = info
        .get("source")
        .and_then(Value::as_u64)
        .ok_or_else(|| QmpError::Protocol {
            operation: "ACPI_DEVICE_OST",
            detail: String::from("matching event has no unsigned source").into_boxed_str(),
        })?;
    if !matches!(source, 0x03 | 0x103) {
        return Ok(None);
    }
    let status = info
        .get("status")
        .and_then(Value::as_u64)
        .ok_or_else(|| QmpError::Protocol {
            operation: "ACPI_DEVICE_OST",
            detail: String::from("matching eject event has no unsigned status").into_boxed_str(),
        })?;

    match status {
        0 | 0x84 => Ok(None),
        0x80..=0x83 => Ok(Some(DeviceDeleteOutcome::GuestRejected {
            device: Some(cpu.device_id.clone()),
            path: None,
            acpi_status: Some(status),
        })),
        _ => Err(QmpError::Protocol {
            operation: "ACPI_DEVICE_OST",
            detail: format!("matching eject event has reserved status {status:#x}")
                .into_boxed_str(),
        }),
    }
}

fn event_matches_cpu(event: &Value, cpu: &HotpluggedCpu) -> bool {
    let Some(data) = event.get("data").and_then(Value::as_object) else {
        return false;
    };
    data.get("device").and_then(Value::as_str) == Some(cpu.device_id.as_ref())
        || data
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|path| qom_path_is_within(path, &cpu.qom_path))
}

fn qom_path_is_within(path: &str, parent: &str) -> bool {
    path.strip_prefix(parent)
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn read_json(reader: &mut BufReader<TcpStream>) -> Value {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn write_json(stream: &mut TcpStream, value: &Value) {
        serde_json::to_writer(&mut *stream, value).unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn qmp_cpu_add_delete_transcript_preserves_slot_properties_and_waits_for_ack() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            write_json(
                &mut stream,
                &json!({"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":2},"package":""},"capabilities":[]}}),
            );
            let mut reader = BufReader::new(stream.try_clone().unwrap());

            let capabilities = read_json(&mut reader);
            assert_eq!(capabilities["execute"], "qmp_capabilities");
            write_json(&mut stream, &json!({"return":{},"id":capabilities["id"]}));

            let query = read_json(&mut reader);
            assert_eq!(query["execute"], "query-hotpluggable-cpus");
            write_json(
                &mut stream,
                &json!({"return":[
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":0,"core-id":0,"thread-id":0},"qom-path":"/machine/unattached/device[0]"},
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":1,"core-id":0,"thread-id":0}}
                ],"id":query["id"]}),
            );

            let add = read_json(&mut reader);
            assert_eq!(add["execute"], "device_add");
            assert_eq!(add["arguments"]["driver"], "qemu64-x86_64-cpu");
            assert_eq!(add["arguments"]["id"], "cpu-hotplug-1");
            assert_eq!(add["arguments"]["socket-id"], 1);
            write_json(&mut stream, &json!({"return":{},"id":add["id"]}));

            let query_after_add = read_json(&mut reader);
            assert_eq!(query_after_add["execute"], "query-hotpluggable-cpus");
            write_json(
                &mut stream,
                &json!({"return":[
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":0,"core-id":0,"thread-id":0},"qom-path":"/machine/unattached/device[0]"},
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":1,"core-id":0,"thread-id":0},"qom-path":"/machine/peripheral/cpu-hotplug-1"}
                ],"id":query_after_add["id"]}),
            );

            let delete = read_json(&mut reader);
            assert_eq!(delete["execute"], "device_del");
            assert_eq!(delete["arguments"]["id"], "cpu-hotplug-1");
            write_json(&mut stream, &json!({"return":{},"id":delete["id"]}));
            write_json(
                &mut stream,
                &json!({"event":"DEVICE_DELETED","data":{"path":"/machine/peripheral/cpu-hotplug-1/lapic"},"timestamp":{"seconds":1,"microseconds":0}}),
            );

            let readd = read_json(&mut reader);
            assert_eq!(readd["execute"], "device_add");
            assert_eq!(readd["arguments"]["driver"], "qemu64-x86_64-cpu");
            assert_eq!(readd["arguments"]["id"], "cpu-hotplug-2");
            assert_eq!(readd["arguments"]["socket-id"], 1);
            write_json(&mut stream, &json!({"return":{},"id":readd["id"]}));

            let query_after_readd = read_json(&mut reader);
            assert_eq!(query_after_readd["execute"], "query-hotpluggable-cpus");
            write_json(
                &mut stream,
                &json!({"return":[
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":0,"core-id":0,"thread-id":0},"qom-path":"/machine/unattached/device[0]"},
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":1,"core-id":0,"thread-id":0},"qom-path":"/machine/peripheral/cpu-hotplug-2"}
                ],"id":query_after_readd["id"]}),
            );
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut client = QmpClient::connect(address, deadline).unwrap();
        let cpu = client
            .add_available_cpu("cpu-hotplug-1", 0, deadline)
            .unwrap();
        client.request_cpu_delete(&cpu, deadline).unwrap();
        assert_eq!(
            client
                .wait_for_device_delete_outcome(&cpu, deadline)
                .unwrap(),
            DeviceDeleteOutcome::Deleted
        );
        let readded = client.readd_cpu(&cpu, "cpu-hotplug-2", deadline).unwrap();
        assert_eq!(readded.properties, cpu.properties);
        assert_eq!(readded.driver, cpu.driver);
        server.join().unwrap();
    }

    #[test]
    fn qmp_selects_available_cpu_by_sorted_topology_coordinate() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            write_json(
                &mut stream,
                &json!({"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":2},"package":""},"capabilities":[]}}),
            );
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let capabilities = read_json(&mut reader);
            write_json(&mut stream, &json!({"return":{},"id":capabilities["id"]}));

            let query = read_json(&mut reader);
            write_json(
                &mut stream,
                &json!({"return":[
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":2,"core-id":0,"thread-id":0}},
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":0,"core-id":0,"thread-id":0},"qom-path":"/machine/unattached/device[0]"},
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":1,"core-id":0,"thread-id":0}}
                ],"id":query["id"]}),
            );

            let add = read_json(&mut reader);
            assert_eq!(add["arguments"]["socket-id"], 2);
            write_json(&mut stream, &json!({"return":{},"id":add["id"]}));
            let query_after_add = read_json(&mut reader);
            write_json(
                &mut stream,
                &json!({"return":[
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":0,"core-id":0,"thread-id":0},"qom-path":"/machine/unattached/device[0]"},
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":1,"core-id":0,"thread-id":0}},
                    {"type":"qemu64-x86_64-cpu","props":{"socket-id":2,"core-id":0,"thread-id":0},"qom-path":"/machine/peripheral/cpu-hotplug-sparse"}
                ],"id":query_after_add["id"]}),
            );
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut client = QmpClient::connect(address, deadline).unwrap();
        let cpu = client
            .add_available_cpu("cpu-hotplug-sparse", 1, deadline)
            .unwrap();
        assert_eq!(cpu.properties["socket-id"], 2);
        server.join().unwrap();
    }

    #[test]
    fn qmp_reports_guest_rejection_as_delete_outcome() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            write_json(
                &mut stream,
                &json!({"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":2},"package":""},"capabilities":[]}}),
            );
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let capabilities = read_json(&mut reader);
            write_json(&mut stream, &json!({"return":{},"id":capabilities["id"]}));
            let delete = read_json(&mut reader);
            write_json(&mut stream, &json!({"return":{},"id":delete["id"]}));
            write_json(
                &mut stream,
                &json!({"event":"DEVICE_UNPLUG_GUEST_ERROR","data":{"device":"cpu-hotplug-1","path":"/machine/peripheral/cpu-hotplug-1"}}),
            );
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut client = QmpClient::connect(address, deadline).unwrap();
        let cpu = HotpluggedCpu {
            device_id: Box::from("cpu-hotplug-1"),
            qom_path: Box::from("/machine/peripheral/cpu-hotplug-1"),
            driver: Box::from("qemu64-x86_64-cpu"),
            properties: Map::new(),
        };
        client.request_cpu_delete(&cpu, deadline).unwrap();
        assert_eq!(
            client
                .wait_for_device_delete_outcome(&cpu, deadline)
                .unwrap(),
            DeviceDeleteOutcome::GuestRejected {
                device: Some(Box::from("cpu-hotplug-1")),
                path: Some(Box::from("/machine/peripheral/cpu-hotplug-1")),
                acpi_status: None,
            }
        );
        server.join().unwrap();
    }

    #[test]
    fn qmp_reports_acpi_device_busy_as_delete_rejection() {
        let cpu = HotpluggedCpu {
            device_id: Box::from("cpu-hotplug-2"),
            qom_path: Box::from("/machine/peripheral/cpu-hotplug-2"),
            driver: Box::from("qemu64-x86_64-cpu"),
            properties: Map::new(),
        };

        assert_eq!(
            acpi_ost_delete_outcome(
                &json!({
                    "event": "ACPI_DEVICE_OST",
                    "data": {
                        "info": {
                            "device": "cpu-hotplug-2",
                            "slot-type": "CPU",
                            "slot": "2",
                            "source": 3,
                            "status": 130
                        }
                    }
                }),
                &cpu,
            )
            .unwrap(),
            Some(DeviceDeleteOutcome::GuestRejected {
                device: Some(Box::from("cpu-hotplug-2")),
                path: None,
                acpi_status: Some(0x82),
            })
        );
    }

    #[test]
    fn qom_subtree_matching_rejects_neighboring_device_prefixes() {
        let cpu = HotpluggedCpu {
            device_id: Box::from("cpu-hotplug-1"),
            qom_path: Box::from("/machine/peripheral/cpu-hotplug-1"),
            driver: Box::from("qemu64-x86_64-cpu"),
            properties: Map::new(),
        };

        assert!(event_matches_cpu(
            &json!({"data":{"path":"/machine/peripheral/cpu-hotplug-1/lapic"}}),
            &cpu,
        ));
        assert!(!event_matches_cpu(
            &json!({"data":{"path":"/machine/peripheral/cpu-hotplug-10/lapic"}}),
            &cpu,
        ));
    }
}
