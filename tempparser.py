import json
import lark
from pathlib import Path

def load_rules():
    try:
        with open(Path(__file__).parent /"rules/lev_device_banner.json") as device_rules_file:
            device_rules = json.load(device_rules_file)
    except Exception:
        print("加载设备指纹规则错误，请重新运行！")
    return device_rules



def match_rules(rules_list: list, env :dict):
    
    grammar = r"""
        ?start: exp
        ?exp  : atom
            | exp "&&" atom             -> and
            | exp "||" atom             -> or
        ?atom : "(" exp ")"
            | func "=" ESCAPED_STRING   -> eq
            | func "!=" ESCAPED_STRING  -> neq
        ?func : "body"                  -> body
            | "header"                  -> header
            | "server"                  -> server
            | "banner"                  -> banner
            | "protocol"                -> protocol
            | "title"                   -> title
            | "cert"                    -> cert
            | "port"                    -> port

        %import common.ESCAPED_STRING
        %import common.WS
        %ignore WS
    """

    parser = lark.Lark(
        grammar,
        parser='lalr',
        lexer='basic',
        propagate_positions=False,
        maybe_placeholders=False,
    )

    def evaluate(tree: lark.tree.Tree, env: dict[str, str]):
        match tree.data:
            case "and":
                return evaluate(tree.children[0], env) and evaluate(tree.children[1], env)
            case "or":
                return evaluate(tree.children[0], env) or evaluate(tree.children[1], env)
            case "eq":
                key = tree.children[0].data
                target = tree.children[1].value[1:-1]
                
                if key in ["body", "banner", "server", "header"]:
                    return target in env[key]
                return env[key] == target
            case "neq":
                key = tree.children[0].data
                target = tree.children[1].value[1:-1]
                if key in ["body", "banner", "server", "header"]:
                    return target not in env[key]
                return env[key] != target
            case _:
                pass
    assets = []
    for rules in load_rules():
        tree = parser.parse(rules["rule"])
        # print(tree.pretty())
        if evaluate(tree, env):
            res = {
                "id":rules["id"],
                "product":rules["product"],
                "product_url":rules["product_url"],
                "second_category_id":rules["second_category_id"],
                "first_category_id":rules["first_category_id"],
                "company":rules["company"],
                "sec_list":[]
            }
            assets.append(res)
    env["assets"] = assets
    return env

