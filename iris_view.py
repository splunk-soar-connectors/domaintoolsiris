ACTION_VIEW_TEMPLATES_DICT = {
    "domain reputation": "iris_risk_score.html",
    "enrich domain": "iris_enrich_domain_profile.html",
    "lookup domain": "iris_domain_profile.html",
}


def display_view(provides, all_app_runs, context):
    context['results'] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)

    return ACTION_VIEW_TEMPLATES_DICT.get(provides)


def get_ctx_result(result):
    ctx_result = {}
    param = result.get_param()
    data = result.get_data()
    if (data):
        ctx_result['param'] = param
        ctx_result['data'] = extract_data(data[0])
        sorted_keys = sorted(ctx_result['data'], key=lambda kv_pair: (not kv_pair.startswith('domain'), kv_pair))
        ctx_result['sorted_data'] = []

        for key in sorted_keys:
          if ctx_result['data'][key] or ctx_result['data'][key] == 0:
            data_count = ""
            if type(ctx_result['data'][key]) is dict:
                value = ctx_result['data'][key].get("value")
                count = ctx_result['data'][key].get("count")
                if value in ("", "None", None):
                    continue
                data_value = value
                data_count = count if count and count != 0 else ""
            else:
                data_value = ctx_result['data'][key]

            is_list = isinstance(ctx_result['data'][key], list)
            key = " ".join(unique_list(key.split()))
            ctx_result["sorted_data"].append((key, data_value, data_count, is_list))

    return ctx_result


def extract_data(data, parent_key="", sep=" "):
    items = []
    for k, v in data.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict) and "value" in v:
            items.append((new_key.replace("_", " "), v))
            continue

        if isinstance(v, dict):
            items.extend(extract_data(v, new_key, sep=sep).items())
        else:
            if isinstance(v, list):
                new_key = new_key.replace("_", " ")
                if new_key in ("domain risk components", "tags"):
                    items.append((new_key, remove_underscore(v)))
                else:
                    items.append((new_key.replace("_", " "), extract_list(v)))
                continue

            items.append((new_key.replace("_", " "), v))

    return dict(items)


def extract_list(value):
    items = []
    for val in value:
        if isinstance(val, dict):
            for k, v in val.items():
                if isinstance(v, list) and "value" in v[0]:
                    val[k] = v[0]

        items.append(val)

    return items


def remove_underscore(value):
    items = []
    for components in value:
        comp_dict = {}
        for k, v in components.items():
            if isinstance(v, str):
                v = v.replace("_", " ")
            if k != "risk_score":
                k = k.replace("_", " ")
            comp_dict[k] = v
        items.append(comp_dict)

    return items


def unique_list(raw_list):
    ulist = []
    [ulist.append(element) for element in raw_list if element not in ulist]

    return ulist
