def unique_list(raw_list):
    ulist = []
    [ulist.append(x) for x in raw_list if x not in ulist]
    return ulist
