# --
# File: iris_view.py
#
# Copyright (c) 2019-2022 DomainTools, LLC
#
# --

import collections
import copy


def unique_list(raw_list):
    ulist = []
    [ulist.append(x) for x in raw_list if x not in ulist]
    return ulist


def create_score_span(score):
    i_score = int(score)
    severity = ""
    if i_score >= 90:
        severity = "high"
    elif i_score >= 70:
        severity = "medium"
    return "<span style='min-width:30px;margin-bottom:2px;' class='label severity " + severity + "'>" + str(score) + "</span>"


def flatten(d, parent_key='', sep=' '):
    items = []
    for k, v in d.items():
        if k != "count":
          k = k.replace("_", " ")
          new_key = parent_key + sep + k if parent_key else k
          new_key = new_key.replace("_", " ").replace("value", "")
          if isinstance(v, collections.MutableMapping):
              items.extend(flatten(v, new_key, sep=sep).items())
          else:
              items.append((new_key, v))

    return dict(items)


def render_list(list_obj):
    ret_str = ""

    if type(list_obj) is not dict and type(list_obj) is not list:
        return str(list_obj).title()
    if type(list_obj) == list and len(list_obj) == 1 and len(list_obj[0]) == 1 and list_obj[0]["value"]:
        return str(list_obj[0]["value"])

    for item in list_obj:
        if type(item) is dict:
            if "name" in item and 'risk_score' in item:
              title_str = item['name'].replace('_', ' ').strip()
              if item['name'] != "zerolist":
                ret_str += "<span style='display:inline-block;min-width:140px;vertical-align:top;'>" \
                           + title_str.title() + ":</span> " + create_score_span(item['risk_score']) + "\n"
              else:
                ret_str += "Zerolist\n"
            else:
              flattened = flatten(item)
              for k in flattened:
                title_str = k.replace('value', '').strip()
                if title_str:
                    title_str = "<span style='display:inline-block;min-width:85px;vertical-align:top;'>"\
                                + title_str.title() + ":</span>"
                ret_str += title_str + render_list(flattened[k]) + "\n"
        elif type(item) is list:
            for list_item in item:
              ret_str += render_list(list_item)
        else:
            ret_str += str(item)

    return ret_str


def get_ctx_result(result):
    ctx_result = {}
    param = result.get_param()
    data = result.get_data()

    ctx_result['param'] = param

    if (data):
        ctx_result['data'] = flatten(data[0] )
        sorted_keys = sorted(ctx_result['data'], key=lambda kv_pair: (not kv_pair.startswith('domain'), kv_pair))
        ctx_result['sorted_data'] = []
        for key in sorted_keys:
          if ctx_result['data'][key] or ctx_result['data'][key] == 0:
            data_value = ctx_result['data'][key]
            if type(ctx_result['data'][key]) is list:
              data_value = render_list(ctx_result['data'][key])
            key = ' '.join(unique_list(key.split()))
            ctx_result['sorted_data'].append((key, data_value))

        # handle risk score item stuff
        if('risk_score' in data[0]['domain_risk']):
            rs_index = [y[0] for y in ctx_result['sorted_data']].index('domain risk score')
            rs_item = ctx_result['sorted_data'].pop(rs_index)
            span = create_score_span(rs_item[1])
            new_tuple = ("domain risk score", span)
            ctx_result['sorted_data'].insert(1, new_tuple)
        else:
            new_tuple = ("domain risk score", "")
            ctx_result['sorted_data'].insert(1, new_tuple)

    return ctx_result


def display_domain_profile(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    return 'iris_domain_profile.html'


def display_risk_score(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = {}
            param = result.get_param()
            data = result.get_data()

            if param:
                ctx_result['param'] = param
            data = result.get_data()

            if data:
                ctx_result = {'data': data[0]}
                risk_scores = ctx_result['data'].get('domain_risk', {}).get('components')
                # Add proximity score to blocklisted domains, see comment below
                if risk_scores:
                    ctx_result['data']["domain_risk"]['components'] = add_proximity_to_blocklisted_domain(risk_scores)

                sorted_data = []
                sorted_data.append(('domain risk score', create_score_span(
                    ctx_result['data'].get('domain_risk', {}).get('risk_score'))))
                sorted_data.append(('domain risk components', render_list(
                    ctx_result['data'].get('domain_risk', {}).get('components', []))))
                ctx_result['sorted_data'] = sorted_data

            results.append(ctx_result)

    return 'iris_risk_score.html'


# Clients want proximity score to show for blocklisted domains. The API removes proximity when it is
# 100 and changes it to blocklist. This is not an optimal solution and should probably be thought out
# to understand the clients needs and goals, then have the backend team work on getting the contract
# the way the clients need it to be. We are doing the same thing in the splunk app.
def add_proximity_to_blocklisted_domain(risk_scores):
    blocklisted = next((item for item in risk_scores if item['name'] == 'blocklist'), None)
    # We only want to do this if the domain is blocklisted
    if blocklisted:
        # Make sure proximity isn't there, this prevents duplicate proximity scores if the Iris Investigate API adds it
        proximity = next((item for item in risk_scores if item['name'] == 'proximity'), None)
        if proximity is None:
            blocklist = copy.deepcopy(blocklisted)
            blocklist['name'] = 'proximity'
            risk_scores.insert(1, blocklist)

    return risk_scores
