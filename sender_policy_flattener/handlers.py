# coding=utf-8
from netaddr import IPNetwork, IPAddress
from dns.name import from_text

import sender_policy_flattener.crawler as crawler


def handle_ip(name, domain, ns):
    yield name


def handle_mx(_, domain, ns):
    answers = ns.resolve(from_text(domain), "mx")
    for mailexchange in answers:
        ips = ns.resolve(mailexchange.exchange, "a")
        for ip in ips:
            yield IPAddress(ip.address)


def handle_mx_domain(name, __, ns):
    answers = ns.resolve(from_text(name), "mx")
    for mailexchange in answers:
        ips = ns.resolve(mailexchange, "a")
        for ip in ips:
            yield IPAddress(ip.address)


def handle_mx_prefix(name, domain, ns):
    _, prefix = name
    answers = ns.resolve(from_text(domain), "mx")
    for mailexchange in answers:
        ips = ns.resolve(mailexchange.exchange, "a")
        for ip in ips:
            yield IPNetwork("{0}/{1}".format(ip, prefix))


def handle_mx_domain_prefix(name, __, ns):
    _, prefix = name
    answers = ns.resolve(from_text(_name), "mx")
    for mailexchange in answers:
        ips = ns.resolve(mailexchange, "a")
        for ip in ips:
            yield IPNetwork("{0}/{1}".format(ip, prefix))


def handle_a(_, domain, ns):
    answers = ns.resolve(from_text(domain), "a")
    for ip in answers:
        yield IPAddress(ip.address)


def handle_a_domain(name, __, ns):
    answers = ns.resolve(from_text(name), "a")
    for ip in answers:
        yield IPAddress(ip.address)


def handle_a_prefix(name, domain, ns):
    _, prefix = name
    answers = ns.resolve(from_text(domain), "a")
    for ip in answers:
        yield IPNetwork("{0}/{1}".format(ip, prefix))


def handle_a_domain_prefix(name, __, ns):
    _, prefix = name
    answers = ns.resolve(from_text(_name), "a")
    for ip in answers:
        yield IPNetwork("{0}/{1}".format(ip, prefix))


def handle_ptr(name, __, ___):
    yield "ptr:{0}".format(name)


def handle_exists(name, __, ___):
    yield "exists:{0}".format(name)


def handle_txt(name, domain, ns):
    yield from crawler.crawl(name, "txt", domain, ns)


handler_mapping = {
    "ip": handle_ip,
    "mx": handle_mx,
    "mx_prefix": handle_mx_prefix,
    "mx_domain": handle_mx_domain,
    "mx_domain_prefix": handle_mx_domain_prefix,
    "a": handle_a,
    "a_domain": handle_a_domain,
    "a_prefix": handle_a_prefix,
    "a_domain_prefix": handle_a_domain_prefix,
    "ptr": handle_ptr,
    "exists": handle_exists,
    "txt": handle_txt
}
