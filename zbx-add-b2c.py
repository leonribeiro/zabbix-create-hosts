#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import argparse
import ipaddress

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
except ImportError:
    from urllib2 import Request, urlopen, URLError, HTTPError

# ===== Defaults editáveis =====
DEFAULT_ZBX_URL = "http://10.0.3.33/zabbix/api_jsonrpc.php"
DEFAULT_TOKEN   = "641d1b61ee4843123e3dc0c03e913ba7dd3cb9f31c660a9d3e5d0e578b73a424"

# Modelos B2C
DEFAULT_MODEL_APP  = "b2c.exemplo.app.host"
DEFAULT_MODEL_DB   = "b2c.exemplo.db.host"
DEFAULT_MODEL_NODE = "b2c.exemplo.node.host"
# ==============================

RPC_ID = 0

def die(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)

def rpc(zbx_url, zbx_token, method, params, timeout=30):

    """

    Zabbix 7.2+: o token vai no header Authorization: Bearer <token>.

    Não incluir "auth" no payload JSON.

    """

    global RPC_ID

    RPC_ID += 1

    payload = {"jsonrpc": "2.0", "method": method, "id": RPC_ID, "params": params}

    data = json.dumps(payload).encode("utf-8")

    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {zbx_token}"}

    try:

        req = Request(zbx_url, data=data, headers=headers)

        resp = urlopen(req, timeout=timeout)

        out = json.loads(resp.read().decode("utf-8"))

    except HTTPError as e:

        try:

            body = e.read().decode("utf-8")

        except Exception:

            body = str(e)

        die("HTTPError {}: {}".format(e.code, body))

    except URLError as e:

        die("URLError: {}".format(e.reason))

    except Exception as e:

        die("Erro inesperado chamando API: {}".format(e))

    if "error" in out:

        err = out["error"]

        msg = err.get("data") or err.get("message") or str(err)

        die("Erro da API em {}: {}".format(method, msg))

    return out["result"]


def host_exists(zbx_url, zbx_token, hostname):
    res = rpc(zbx_url, zbx_token, "host.get", {
        "filter": {"host": [hostname]},
        "output": ["hostid", "host"]
    })
    return (len(res) > 0, (res[0]["hostid"] if res else None))

def get_model(zbx_url, zbx_token, model_host):
    res = rpc(zbx_url, zbx_token, "host.get", {
        "filter": {"host": [model_host]},
        "output": "extend",
        "selectGroups": "extend",
        "selectTemplates": "extend",
        "selectParentTemplates": "extend",
        "selectTags": "extend",
        "selectMacros": "extend",
        "selectInterfaces": "extend",
        "selectInventory": "extend",
        "selectInventoryMasterItems": "extend"
    })
    if not res:
        die("Host modelo não encontrado: {}".format(model_host))
    return res[0]

def minimalize(list_of_dicts, key):
    out = []
    for d in list_of_dicts or []:
        if key in d:
            out.append({key: d[key]})
    return out

def parse_kv_list(items, allow_empty_value=False):
    parsed = []
    for item in items or []:
        if "=" not in item:
            if allow_empty_value:
                k, v = item, ""
            else:
                die("Par inválido (esperado chave=valor): {}".format(item))
        else:
            k, v = item.split("=", 1)
        parsed.append((k, v))
    return parsed

def build_interfaces_from_model(model, new_ip):

    interfaces = model.get("interfaces", []) or []

    result = []

    agent_main_set = False



    for itf in interfaces:

        t = int(itf.get("type", 1))

        m = int(itf.get("main", 0))

        useip = int(itf.get("useip", 1))

        ip = itf.get("ip", "")

        dns = itf.get("dns", "")

        port = itf.get("port", "10050")



        itf_new = {

            "type": t,

            "main": m,

            "useip": useip,

            "ip": ip,

            "dns": dns,

            "port": str(port),

        }

        # Só SNMP (type=2) aceita "bulk"

        if t == 2:

            try:

                itf_new["bulk"] = int(itf.get("bulk", 1))

            except Exception:

                itf_new["bulk"] = 1



        if t == 1 and m == 1:

            itf_new["useip"] = 1

            itf_new["ip"] = new_ip

            itf_new["dns"] = ""

            agent_main_set = True

        result.append(itf_new)



    if not result:

        result.append({"type": 1, "main": 1, "useip": 1, "ip": new_ip, "dns": "", "port": "10050"})

        agent_main_set = True

    if not agent_main_set:

        result.append({"type": 1, "main": 1, "useip": 1, "ip": new_ip, "dns": "", "port": "10050"})



    return result


def ensure_macro(macros, macro_name, value):
    found = False
    for m in macros:
        if m.get("macro") == macro_name:
            m["value"] = value
            found = True
            break
    if not found:
        macros.append({"macro": macro_name, "value": value})
    return macros

def group_get_by_name(zbx_url, zbx_token, name):
    res = rpc(zbx_url, zbx_token, "hostgroup.get", {"filter": {"name": [name]}, "output": ["groupid", "name"]})
    return res[0]["groupid"] if res else None

def group_ensure(zbx_url, zbx_token, name):
    gid = group_get_by_name(zbx_url, zbx_token, name)
    if gid:
        return gid
    res = rpc(zbx_url, zbx_token, "hostgroup.create", {"name": name})
    return res["groupids"][0]

def merge_groups_by_ids(existing_groups, extra_group_ids):
    base = []
    seen = set()
    for g in existing_groups or []:
        gid = str(g.get("groupid"))
        if gid and gid not in seen:
            base.append({"groupid": gid})
            seen.add(gid)
    for gid in extra_group_ids or []:
        gid = str(gid)
        if gid and gid not in seen:
            base.append({"groupid": gid})
            seen.add(gid)
    return base

def clone_host(zbx_url, zbx_token, model_host, new_hostname, new_ip,
               proxy_hostid=None, extra_group_ids=None, extra_tags=None,
               extra_macros=None, copy_inventory=True, visible_name=None,
               dry_run=False):
    exists, _hostid = host_exists(zbx_url, zbx_token, new_hostname)
    if exists:
        return {"host": new_hostname, "status": "Host já existe"}

    model = get_model(zbx_url, zbx_token, model_host)

    groups = minimalize(model.get("groups"), "groupid")
    groups = merge_groups_by_ids(groups, extra_group_ids)

    templates = minimalize(model.get("templates"), "templateid")
    parent_templates = minimalize(model.get("parentTemplates"), "templateid")
    if parent_templates:
        merged = {t["templateid"]: t for t in (templates + parent_templates)}
        templates = list(merged.values())

    # Tags (modelo + extras)
    tags = []
    for t in model.get("tags") or []:
        tag = {"tag": t.get("tag", "")}
        if "value" in t:
            tag["value"] = t.get("value", "")
        tags.append(tag)
    for (k, v) in extra_tags or []:
        tags.append({"tag": k, "value": v})

    # Macros (modelo + extras)
    macros = []
    for m in model.get("macros") or []:
        entry = {"macro": m.get("macro", ""), "value": m.get("value", "")}
        if "type" in m:
            try:
                entry["type"] = int(m.get("type", 0))
            except Exception:
                pass
        macros.append(entry)
    for (mk, mv) in extra_macros or []:
        macros = ensure_macro(macros, mk, mv)

    interfaces = build_interfaces_from_model(model, new_ip)
    # Sanitiza: remove "bulk" de interfaces que não são SNMP (type=2)

    for _if in interfaces:

        if int(_if.get("type", 1)) != 2:

            _if.pop("bulk", None)

    params = {
        "host": new_hostname,
        "name": (visible_name or new_hostname),
        "groups": groups,
        "templates": templates,
        "tags": tags,
        "macros": macros,
        "interfaces": interfaces
    }
    if proxy_hostid:
        params["proxy_hostid"] = str(proxy_hostid)
    if copy_inventory:
        inv = model.get("inventory")
        if isinstance(inv, dict) and len(inv) > 0:
            params["inventory"] = inv

    if dry_run:
        return {"host": new_hostname, "status": "Dry-run: criação simulada", "params": params}

    _res = rpc(zbx_url, zbx_token, "host.create", params)
    return {"host": new_hostname, "status": "Host criado com sucesso"}

def validate_ip(value, label):
    try:
        ipaddress.ip_address(value)
        return value
    except Exception:
        die("IP inválido para {}: {}".format(label, value))

def parse_args():
    p = argparse.ArgumentParser(description="Criar hosts B2C (APP/DB/NODE) clonando de modelos b2c.exemplo.*.")
    p.add_argument("--shop", help="shop_name (ex: novaloja2)")

    # IPs dos 3 hosts
    p.add_argument("--app-ip", help="IP do host APP")
    p.add_argument("--db-ip", help="IP do host DB")
    p.add_argument("--node-ip", help="IP do host NODE")

    # URLs para {$URL_TO_CHECK} (valores por host específico)
    p.add_argument("--url-admin-checkout", help="URL ADMIN de checkout (aplicada no host APP) -> {$URL_TO_CHECK}")
    p.add_argument("--url-front",          help="URL de FRONT (aplicada no host NODE) -> {$URL_TO_CHECK}")

    p.add_argument("--url", help="Zabbix API URL (default/env ZBX_URL)")
    p.add_argument("--token", help="Zabbix API token (default/env ZBX_TOKEN)")

    p.add_argument("--model-app",  default=DEFAULT_MODEL_APP,  help="Host modelo APP")
    p.add_argument("--model-db",   default=DEFAULT_MODEL_DB,   help="Host modelo DB")
    p.add_argument("--model-node", default=DEFAULT_MODEL_NODE, help="Host modelo NODE")

    # Extras
    p.add_argument("--proxy-hostid", help="Proxy hostid para os novos hosts")
    p.add_argument("--group", action="append", help="GroupID extra (repetível)", default=[])
    p.add_argument("--add-tag", action="append", help="Tag extra no formato key=value (repetível)", default=[])
    p.add_argument("--add-macro", action="append", help="Macro extra no formato {$NOME}=valor (repetível)", default=[])

    # PROD/HML via flags
    p.add_argument("--prod", action="store_true", help="Adicionar no grupo PROD")
    p.add_argument("--hml",  action="store_true", help="Adicionar no grupo HML")

    # Controles
    p.add_argument("--no-copy-inventory", action="store_true", help="Não copiar inventário do modelo")
    p.add_argument("--visible-name", help="Nome visível (se diferente do técnico)")
    p.add_argument("--dry-run", action="store_true", help="Simula, não cria")
    p.add_argument("--json-logs", action="store_true", help="Saída em linhas JSON")
    return p.parse_args()

def log_line(msg, json_mode=False, **extra):
    if json_mode:
        obj = {"message": msg}
        if extra:
            obj.update(extra)
        print(json.dumps(obj, ensure_ascii=False))
    else:
        print(msg)

def main():
    args = parse_args()

    if args.prod and args.hml:
        die("Use apenas uma das flags: --prod OU --hml.")

    zbx_url = args.url or os.environ.get("ZBX_URL") or DEFAULT_ZBX_URL
    zbx_tok = args.token or os.environ.get("ZBX_TOKEN") or DEFAULT_TOKEN

    shop = args.shop
    app_ip = args.app_ip
    db_ip  = args.db_ip
    node_ip = args.node_ip
    url_admin_checkout = args.url_admin_checkout
    url_front = args.url_front

    # Interativo se faltar algo
    try:
        if not shop:
            shop = input("Informe o shop_name (ex: novaloja2): ").strip()
        if not app_ip:
            app_ip = input("IP do host APP: ").strip()
        if not db_ip:
            db_ip = input("IP do host DB: ").strip()
        if not node_ip:
            node_ip = input("IP do host NODE: ").strip()
        if not url_admin_checkout:
            url_admin_checkout = input("Insira a URL ADMIN de checkout (para APP): ").strip()
        if not url_front:
            url_front = input("Insira a URL de FRONT (para NODE): ").strip()
    except KeyboardInterrupt:
        die("\nCancelado.")

    if not shop:
        die("shop_name é obrigatório.")
    validate_ip(app_ip, "APP")
    validate_ip(db_ip, "DB")
    validate_ip(node_ip, "NODE")

    # >>>> Nomes dos novos hosts (b2c.{shop}.*) <<<<
    new_app  = "b2c.{}.app.host".format(shop)
    new_db   = "b2c.{}.db.host".format(shop)
    new_node = "b2c.{}.node.host".format(shop)

    # Tags comuns e macros genéricas passadas via --add-*
    extra_tags_cli   = parse_kv_list(args.add_tag)
    extra_macros_cli = parse_kv_list(args.add_macro, allow_empty_value=True)

    copy_inventory = (not args.no_copy_inventory)

    # Decide grupos destino (cria se não existir)
    extra_group_ids = list(args.group or [])
    if args.prod:
        gid = group_ensure(zbx_url, zbx_tok, "PROD")
        extra_group_ids.append(gid)
    if args.hml:
        gid = group_ensure(zbx_url, zbx_tok, "HML")
        extra_group_ids.append(gid)

    results = []
    partial = False

    # ---- APP (com {$URL_TO_CHECK} = url_admin_checkout)
    extra_macros_app = list(extra_macros_cli)
    if url_admin_checkout:
        extra_macros_app.append(("{$URL_TO_CHECK}", url_admin_checkout))

    res_app = clone_host(
        zbx_url, zbx_tok,
        args.model_app, new_app, app_ip,
        proxy_hostid=args.proxy_hostid,
        extra_group_ids=extra_group_ids,
        extra_tags=extra_tags_cli,
        extra_macros=extra_macros_app,
        copy_inventory=copy_inventory,
        visible_name=args.visible_name,
        dry_run=args.dry_run
    )
    results.append(res_app)

    # ---- DB (sem URL_TO_CHECK)
    res_db = clone_host(
        zbx_url, zbx_tok,
        args.model_db, new_db, db_ip,
        proxy_hostid=args.proxy_hostid,
        extra_group_ids=extra_group_ids,
        extra_tags=extra_tags_cli,
        extra_macros=extra_macros_cli,
        copy_inventory=copy_inventory,
        visible_name=args.visible_name,
        dry_run=args.dry_run
    )
    results.append(res_db)

    # ---- NODE (com {$URL_TO_CHECK} = url_front)
    extra_macros_node = list(extra_macros_cli)
    if url_front:
        extra_macros_node.append(("{$URL_TO_CHECK}", url_front))

    res_node = clone_host(
        zbx_url, zbx_tok,
        args.model_node, new_node, node_ip,
        proxy_hostid=args.proxy_hostid,
        extra_group_ids=extra_group_ids,
        extra_tags=extra_tags_cli,
        extra_macros=extra_macros_node,
        copy_inventory=copy_inventory,
        visible_name=args.visible_name,
        dry_run=args.dry_run
    )
    results.append(res_node)

    # Saída
    exit_code = 0
    for r in results:
        msg = "{}: {}".format(r.get("host"), r.get("status"))
        log_line(msg, args.json_logs, host=r.get("host"), status=r.get("status"))
        if r.get("status") == "Host já existe":
            partial = True
    if partial and not args.dry_run:
        exit_code = 2
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
