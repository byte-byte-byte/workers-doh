const dnsQueryPath = '/dns-query'; // DoH request path
const resolvePath = '/resolve'; // resolve request path
//const upstream = 'https://1.1.1.1/dns-query'
//const upstream = 'https://dns.nextdns.io/dns-query'
const upstream = 'https://dns.google/resolve'

export default {
    async fetch(request, env, ctx) {
        const clientUrl = new URL(request.url);
        const clientIp = request.headers.get('CF-Connecting-IP');
        if (!clientIp) {
            return new Response('Missing client IP', { status: 400 });
        }
        try {
            if (clientUrl.pathname === dnsQueryPath) {
                // Processing standard DoH requests.
                switch (request.method) {
                    case 'GET':
                        return handleDoHGetRequest(request, clientUrl, clientIp);
                    case 'POST':
                        return handleDoHPostRequest(request, clientIp);
                    default:
                        return new Response('Method not allowed', { status: 405 });
                }
            } else if (clientUrl.pathname === resolvePath) {
                // Process /resolve?name= request.
                return handleResolveRequest(request, clientUrl, clientIp);
            }
        } catch { }
        return new Response('' + clientIp);
    },
};

async function handleRequestDoHByDns(dnsValue, clientIp, domain) {
    const maskedIp = maskIpAddress(clientIp); // Obfuscate client IPs
    const upstreamUrl = new URL(upstream);
    upstreamUrl.searchParams.set('dns', dnsValue);
    upstreamUrl.searchParams.set('edns_client_subnet', `${maskedIp}`);
    console.log('dns: ' + upstreamUrl);

    const upstreamRequest = new Request(upstreamUrl.toString(), {
        headers: {
            'accept': 'application/dns-message',
            'content-type': 'application/dns-message',
        },
        method: 'GET',
    });
    upstreamRequest.headers.set('host', upstreamUrl.hostname);

    let response = await fetch(upstreamRequest);
    if (domain) {
        const dnsResponse = await response.arrayBuffer();
        // Extract domain names
        const domain = decodeDnsQueryName(dnsValue);
        const jsonResponse = parseDnsResponse(new Uint8Array(dnsResponse), domain);
        return new Response(JSON.stringify(jsonResponse, null, 2), {
            headers: {
                'content-type': 'application/json',
            },
        });
    }
    return response; // Returns a binary DNS message
}
function buildTypeRequest(domain, maskedIp, type) {
    const upstreamUrl = new URL(upstream);
    upstreamUrl.searchParams.set('name', domain);
    if(type=='AAAA'){
        upstreamUrl.searchParams.set('type', type);
    } 
    upstreamUrl.searchParams.set('edns_client_subnet', `${maskedIp}`);
    console.log(upstreamUrl);

    const upstreamRequest = new Request(upstreamUrl.toString(), {
        headers: {
            'accept': 'application/dns-json',
            'content-type': 'application/dns-json',
        },
        method: 'GET',
    });
    upstreamRequest.headers.set('host', upstreamUrl.hostname);
    return upstreamRequest;
}

async function handleRequestDoHByName(domain, clientIp, dnsValue, reqType) {
    const maskedIp = maskIpAddress(clientIp); // Obfuscate client IPs  
    let json;
    if(reqType===28){
        let res = await fetch(buildTypeRequest(domain, maskedIp, 'AAAA'));
        json = await res.json();
    }else{
        let res = await fetch(buildTypeRequest(domain, maskedIp, 'A'));
        json = await res.json();
    }
    
    if (dnsValue) {
        const dnsQueryBuffer = base64urlDecode(dnsValue);
        const queryBytes = new Uint8Array(dnsQueryBuffer);
        const wantDnssec = detectDnssecOK(queryBytes);
        console.log(dnsValue + ' , qtype:' + reqType);
        const dnsMessage = buildDnsResponse(queryBytes, json, wantDnssec);
        return new Response(dnsMessage, {
            status: 200,
            headers: {
                'Content-Type': 'application/dns-message',
            }
        });
    }

    return new Response(JSON.stringify(json), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
        }
    });
}

/**
 * Handle standard DoH GET requests (/dns-query)
 * @param {Request} request
 * @param {URL} clientUrl
 * @param {string} clientIp
 */
async function handleDoHGetRequest(request, clientUrl, clientIp) {
    var name = clientUrl.searchParams.get('name');
    var dnsValue = clientUrl.searchParams.get('dns');
    if (!name && !dnsValue) {
        return new Response('Missing DNS parameter', { status: 400 });
    }
    const acceptHeader = request.headers.get('accept');
    if (!acceptHeader || (!acceptHeader.includes('application/dns-message') && !acceptHeader.includes('application/dns-json') && !acceptHeader.includes('text/html'))) {
        return new Response('Invalid request header: Accept must be application/dns-message or application/dns-json', { status: 400 });
    }
    //return handleRequestDoHByDns(dnsValue,clientIp,false)
    let qtype = 1;
    if (dnsValue) {
        const dnsQueryBuffer = base64urlDecode(dnsValue);
        const queryBytes = new Uint8Array(dnsQueryBuffer);
        name = decodeDnsQueryName(dnsValue)
        qtype = extractQType(queryBytes);
    }
    return await handleRequestDoHByName(name, clientIp, dnsValue, qtype);
}


async function handleDoHPostRequest(request, clientIp) {
    if (request.headers.get('content-type') !== 'application/dns-message') {
        return new Response('Invalid request header', { status: 400 });
    }

    const dnsQueryBuffer = await request.arrayBuffer();
    const dnsValue = base64urlEncode(dnsQueryBuffer);
    const queryBytes = new Uint8Array(dnsQueryBuffer);
    const domain = extractQName(queryBytes)
    const qtype = extractQType(queryBytes);
    return await handleRequestDoHByName(domain, clientIp, dnsValue, qtype);

}
async function handleResolveRequest(request, clientUrl, clientIp) {
    if (request.method !== 'GET') {
        return new Response('Method not allowed', { status: 405 });
    }

    const domain = clientUrl.searchParams.get('name');
    if (!domain) {
        return new Response('Missing name parameter', { status: 400 });
    }
    const dnsValue = generateDnsQuery(domain, 'A');
    return await handleRequestDoHByName(domain, clientIp, false);

}
/**
 * Generate DNS requests.
 * @param {string} domain 
 * @param {string} type 
 * @returns {object} dns={base64}
 */
function generateDnsQuery(domain, type) {
    const header = new Uint8Array([
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ]);

    // question section
    const labels = domain.split('.').filter(label => label.length > 0);
    let question = [];
    for (const label of labels) {
        question.push(label.length);
        for (let i = 0; i < label.length; i++) {
            question.push(label.charCodeAt(i));
        }
    }
    question.push(0); // end flg

    // Query type and class (A record, IN class)
    const typeA = type === 'A' ? [0x00, 0x01] : [0x00, 0x1c]; // A 或 AAAA
    const classIN = [0x00, 0x01]; // IN
    question.push(...typeA, ...classIN);

    const dnsMessage = new Uint8Array(header.length + question.length);
    dnsMessage.set(header, 0);
    dnsMessage.set(question, header.length);

    // Convert to Base64.
    const base64 = btoa(String.fromCharCode(...dnsMessage)).replace(/=/g, '');
    return base64;
}




/**
 * Parse the DNS response and convert it into JSON format.
 * @param {Uint8Array} buffer DNS Respond to binary data.
 * @param {string} domain The domain name inquired.
 * @returns {object} DNS response in JSON format.
 */
function parseDnsResponse(buffer, domain) {
    const response = {
        Status: 0, // Default success, simplified handling.
        Question: [{ name: domain, type: 'A' }],
        Answer: [],
    };

    // Analyze the DNS header (12 bytes)
    const qdcount = (buffer[4] << 8) | buffer[5]; // Number of Questions
    const ancount = (buffer[6] << 8) | buffer[7]; // Number of Answer

    // Skip the introductory and questioning sections (simplified, assuming one question).
    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
        while (buffer[offset] !== 0) offset++; // Skip the domain name.
        offset += 5; // Skip end marker (0)   Type (2)   Class (2)
    }

    // Analysis of the answer section.
    for (let i = 0; i < ancount; i++) {
        // Skip the domain name (possibly using compressed pointers).
        if ((buffer[offset] & 0xc0) === 0xc0) {
            offset += 2; // The pointer occupies 2 bytes.
        } else {
            while (buffer[offset] !== 0) offset++;
            offset++;
        }

        const type = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 4; // Skip Type (2) Class (2)
        const ttl = (buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4; // Skip TTL
        const rdlength = (buffer[offset] << 8) | buffer[offset + 1];
        
        offset += 2; // Skip data length

        let data = '';
        if (type === 1) { // A Record
            data = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
            offset += rdlength;
        } else if (type === 28) { // AAAA Record
            const parts = [];
            for (let j = 0; j < rdlength; j += 2) {
                parts.push(((buffer[offset + j] << 8) | buffer[offset + j + 1]).toString(16));
            }
            data = parts.join(':').replace(/(:0)+/, ':');
            offset += rdlength;
        } else {
            offset += rdlength; // Skip unsupported record types.
            continue;
        }

        response.Answer.push({
            name: domain,
            type: type === 1 ? 'A' : 'AAAA',
            TTL: ttl,
            data: data,
        });
    }

    return response;
}

// === Constructing DNS Responses ===
function buildDnsResponse(query, json, includeEdns) {
    const header = query.slice(0, 12);
    const question = query.slice(12);

    const id = header.slice(0, 2);
    const flags = new Uint8Array([0x81, 0x80]); // Standard Response + Recursion
    const qdcount = header.slice(4, 6);
    const ancount = new Uint8Array([0x00, json.Answer?.length || 0x00]);
    const nscount = new Uint8Array([0x00, 0x00]);
    const arcount = new Uint8Array([0x00, includeEdns ? 1 : 0]);

    const answerRecords = [];
    const offsetMap = new Map();
    if (json.Answer) {
        for (const answer of json.Answer) {
            const type = answer.type;           
            const currentLen =concatUint8Arrays([
                id, flags, qdcount, ancount, nscount, arcount,
                question,
                ...answerRecords
            ]).length;

            const rdata = buildRdata(type, answer.data,offsetMap,currentLen);
            if (!rdata) continue;
            let offset = 0x0c;           
            if (offsetMap.has(answer.name)) {
                offset = offsetMap.get(answer.name);
                console.log('offset:'+offset);
            }
            console.log('name:'+answer.name+', offset:'+offset);

            const record = concatUint8Arrays([
                //new Uint8Array([0xc0, 0x0c]), // NAME (pointer to QNAME)
                new Uint8Array([0xc0, offset]),
                new Uint8Array([(type >> 8) & 0xff, type & 0xff]),
                new Uint8Array([0x00, 0x01]), // CLASS IN
                encodeTTL(answer.TTL),
                new Uint8Array([(rdata.length >> 8) & 0xff, rdata.length & 0xff]),
                rdata
            ]);

            answerRecords.push(record);
        }
    }

    const sections = [
        id, flags, qdcount, ancount, nscount, arcount,
        question,
        ...answerRecords
    ];

    if (includeEdns) {
        sections.push(buildEdns0Response());
    }

    return concatUint8Arrays(sections);
}

function encodeTTL(ttl) {
    return new Uint8Array([
        (ttl >> 24) & 0xff,
        (ttl >> 16) & 0xff,
        (ttl >> 8) & 0xff,
        ttl & 0xff
    ]);
}
// ===== RDATA Construction =====
function buildRdata(type, data,offsetMap,currentLen) {
    console.log('type:'+type+', data:'+data);    
    if (type === 1) { // A
        return new Uint8Array(data.split('.').map(n => parseInt(n, 10)));
    } else if (type === 2||type === 5) {//2-NS 5-CNAME
        if (!offsetMap.has(data)) {
            let name=data;
            if (name[name.length - 1] == '.') {
                name = name.substring(0, name.length - 1)
            }
            offsetMap.set(name, currentLen + 12)
            console.log('set map:'+data+',offset:'+(currentLen + 12));
        }
        return dnsNameToLabels(data);
    } else if (type === 28) { // AAAA
        return parseIPv6ToBytes(data);
    } else if (type === 15) { // MX
        const [priorityStr, ...hostParts] = data.split(' ');
        const priority = parseInt(priorityStr);
        const hostname = hostParts.join(' ');
        return concatUint8Arrays([
            new Uint8Array([(priority >> 8) & 0xff, priority & 0xff]),
            dnsNameToLabels(hostname)
        ]);
    } else if (type === 16) {//TXT
        const texts = Array.isArray(data) ? data : [data];
        const parts = texts.map(t => {
            const encoded = new TextEncoder().encode(t);
            return new Uint8Array([encoded.length, ...encoded]);
        })
        return concatUint8Arrays(parts);
    } else if (type === 46) { // RRSIG (DNSSEC signature records, processed as is for simplification.)
        return new TextEncoder().encode(data);
    } else if (type === 6) { // SOA   
        const [mname, rname, serial, refresh, retry, expire, minimum] = data.split(' ');
        return concatUint8Arrays([
            dnsNameToLabels(mname),
            dnsNameToLabels(rname),
            encodeUint32(serial),
            encodeUint32(refresh),
            encodeUint32(retry),
            encodeUint32(expire),
            encodeUint32(minimum)
        ]);
    }
    else if (type === 33) { // SRV
        const [priority, weight, port, target] = data.split(' ');
        const targetBytes = dnsNameToLabels(target);
        return new Uint8Array([
            (priority >> 8) & 0xff, priority & 0xff,
            (weight >> 8) & 0xff, weight & 0xff,
            (port >> 8) & 0xff, port & 0xff,
            ...targetBytes
        ]);
    }
    return null; // unsupported
}
// ===== EDNS0 OPT Pseudo Record Construction =====
function buildEdns0Response() {
    return new Uint8Array([
        0x00,                   // NAME = root
        0x00, 0x29,             // TYPE = OPT
        0x10, 0x00,             // UDP payload size = 4096
        0x00,                   // Extended RCODE
        0x00,                   // EDNS version
        0x80, 0x00,             // DO = 1 (bit 15 set)
        0x00, 0x00              // RDLENGTH = 0
    ]);
}

/**
* Obfuscate IP addresses to protect privacy.
* @param {string} ip Original IP address (IPv4 or IPv6)
* @returns {string} The obscured IP and subnet mask (such as "203.0.113.0/24" or "2001:db8::/48")
*/
function maskIpAddress(ip) {
    if (ip.includes(':')) {
        // IPv6：Retain the first 48 positions (3 segments), and set the remaining 80 positions to zero.
        const parts = ip.split(':').slice(0, 3).concat(['0', '0', '0', '0', '0']);
        return `${parts.join(':')}/48`;
    } else {
        // IPv4：Retain the first 24 digits (3 parts), setting the last part to zero.
        const parts = ip.split('.').slice(0, 3).concat(['0']);
        return `${parts.join('.')}/24`;
    }
}

function concatUint8Arrays(arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}
function dnsNameToLabels(name) {
    const parts = name.split('.');
    const bytes = [];
    for (const part of parts) {
        const label = new TextEncoder().encode(part);
        bytes.push(label.length, ...label);
    }
    if(bytes[bytes.length - 1]!=0){
        bytes.push(0); // terminator
    }  
    return new Uint8Array(bytes);
}

// === Base64url decoding ===
function base64urlDecode(input) {
    // Replace the special characters in base64url.
    input = input.replace(/-/g, '+').replace(/_/g, '/');
    // Complete the padding.
    while (input.length % 4 !== 0) input += '=';
    const binary = atob(input);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
// === base64url encoding ===
function base64urlEncode(buffer) {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}



/**
* Extract the domain name from the Base64 encoded DNS query.
* @param {string} dnsQueryBase64 Base64 encoded DNS query
* @returns {string} Domain name
*/
function decodeDnsQueryName(dnsQueryBase64) {
    try {
        const dnsQuery = new Uint8Array(
            atob(dnsQueryBase64)
                .split('')
                .map(c => c.charCodeAt(0))
        );

        let offset = 12; // Skip the DNS header (12 bytes)
        let name = [];
        while (dnsQuery[offset] !== 0) {
            const len = dnsQuery[offset];
            offset++;
            const label = String.fromCharCode(...dnsQuery.slice(offset, offset + len));
            name.push(label);
            offset += len;
        }
        return name.join('.');
    } catch (e) {
        return 'unknown'; 
    }
}

function extractQName(bytes) {
    let i = 12; // QNAME starts to offset (Header occupies 12 bytes).
    const labels = [];

    while (i < bytes.length) {
        const len = bytes[i];
        if (len === 0) break;
        if (i + len >= bytes.length) return null;

        const label = Array.from(bytes.slice(i + 1, i + 1 + len))
            .map(c => String.fromCharCode(c))
            .join('');
        labels.push(label);
        i += len + 1;
    }

    return labels.join('.');
}
//Check the query type.
function extractQType(bytes) {
    const qtypeOffset = bytes.findIndex((b, i) => i >= 12 && bytes[i] === 0x00) + 1;
    if (qtypeOffset + 2 > bytes.length) return null;
    return (bytes[qtypeOffset] << 8 | bytes[qtypeOffset + 1]);
}

// ===== Check DNSSEC OK =====
function detectDnssecOK(query) {
    const arcount = (query[10] << 8) | query[11];
    if (arcount === 0) return false;

    let i = 12;
    const qdcount = (query[4] << 8) | query[5];
    for (let q = 0; q < qdcount; q++) {
        while (query[i] !== 0) i += query[i] + 1;
        i += 5;
    }

    for (let a = 0; a < arcount; a++) {
        if (query[i] !== 0x00) break;
        const type = (query[i + 1] << 8) | query[i + 2];
        if (type === 41) {
            const flags = (query[i + 7] << 8) | query[i + 8];
            return (flags & 0x8000) !== 0;
        }
        break;
    }

    return false;
}

function parseIPv6ToBytes(ipv6) {
    const segments = ipv6.split('::');
    let head = segments[0] ? segments[0].split(':').map(h => parseInt(h || '0', 16)) : [];
    let tail = segments[1] ? segments[1].split(':').map(h => parseInt(h || '0', 16)) : [];
    const total = head.length + tail.length;
    const zeros = Array(8 - total).fill(0);
    const full = [...head, ...zeros, ...tail].slice(0, 8);
    return new Uint8Array(full.flatMap(part => [(part >> 8) & 0xff, part & 0xff]));
}

function encodeUint32(val) {
    const num = typeof val === 'string' ? parseInt(val, 10) : val;
    return new Uint8Array([
        (num >>> 24) & 0xff,
        (num >>> 16) & 0xff,
        (num >>> 8) & 0xff,
        num & 0xff
    ]);
}
