def unique_list(raw_list):
    ulist = []
    [ulist.append(x) for x in raw_list if x not in ulist]
    return ulist


def display_domain_profile(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    return 'iris_domain_profile.html'


def get_ctx_result(result):
    ctx_result = {}
    param = result.get_param()
    data = result.get_data()

    ctx_result['param'] = param

    if (data):
        ctx_result['data'] = extract_data(data[0])
        sorted_keys = sorted(ctx_result['data'], key=lambda kv_pair: (not kv_pair.startswith('domain'), kv_pair))
        ctx_result['sorted_data'] = []
        for key in sorted_keys:
          is_list = False
          if ctx_result['data'][key] or ctx_result['data'][key] == 0:
            data_count = ""
            if type(ctx_result['data'][key]) is dict:
                value = ctx_result['data'][key].get("value")
                count = ctx_result['data'][key].get("count")
                if value in ("", "None", None):
                    continue
                data_value = value
                data_count = count if count and count != 0 else ""
            elif type(ctx_result['data'][key]) is list:
                is_list = True
                data_value = ctx_result['data'][key]
            else:
                data_value = ctx_result['data'][key]

            key = " ".join(unique_list(key.split()))
            ctx_result["sorted_data"].append((key, data_value, data_count, is_list))

    return ctx_result


def extract_data(d, parent_key="", sep=" "):
    items = []
    for k, v in d.items():
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


def extract_list(v):
    items = []
    for val in v:
        if isinstance(val, dict):
            for key, value in val.items():
                if isinstance(value, list) and "value" in value[0]:
                    val[key] = value[0]
        items.append(val)
    return items


def remove_underscore(v):
    items = []
    for components in v:
        comp_dict = {}
        for key, value in components.items():
            if isinstance(value, str):
                value = value.replace("_", " ")
            if key != "risk_score":
                key = key.replace("_", " ")
            comp_dict[key] = value
        items.append(comp_dict)
    return items
