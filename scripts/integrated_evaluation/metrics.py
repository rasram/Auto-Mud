"""Independent evaluation counts; unavailable observations are never benign."""
from collections import Counter


def detection(rows):
    counts = Counter()
    for row in rows:
        if not row.get('eligible', True):
            counts['excluded'] += 1
            continue
        label, flag = row['label'], row['flag']
        if label not in (0, 1):
            raise ValueError('Truth must be a frozen binary annotation')
        counts['population'] += 1
        if flag is None:
            counts['unscored_positive' if label else 'unscored_negative'] += 1
        elif not isinstance(flag, bool):
            raise ValueError('Prediction must be boolean or unavailable')
        else:
            counts[('TP' if flag else 'FN') if label else ('FP' if flag else 'TN')] += 1
    result = {k: counts[k] for k in ['TP', 'FP', 'TN', 'FN', 'unscored_positive', 'unscored_negative', 'population', 'excluded']}
    def div(a, b):
        return a / b if b else None
    tp, fp, tn, fn, up, un = (result[k] for k in ['TP', 'FP', 'TN', 'FN', 'unscored_positive', 'unscored_negative'])
    result.update(precision=div(tp, tp + fp), population_recall=div(tp, tp + fn + up), population_f1=div(2 * tp, 2 * tp + fp + fn + up), fpr=div(fp, fp + tn), coverage=div(tp + fp + tn + fn, result['population']))
    return result


def permission_oracle(row, address_to_device, rules):
    """Literal policy-matrix lookup, independent of production MUDEngine."""
    origin = address_to_device.get(row['orig_h'])
    target = address_to_device.get(row['resp_h'])
    if origin is None:
        return 'outside_household_origin'
    if target is None:
        return 'unsupported_external_policy'
    key = (origin, target, row['proto'], row.get('resp_p'))
    return 'allowed' if key in rules else 'denied'


def policy_confusion(rows):
    counts = Counter()
    for row in rows:
        expected, actual = row['expected'], row['actual']
        if expected not in ('allowed', 'denied'):
            counts['unsupported'] += 1
            continue
        counts['eligible'] += 1
        if actual not in ('allowed', 'denied'):
            counts['unavailable_forbidden' if expected == 'denied' else 'unavailable_permitted'] += 1
        else:
            counts[('TP' if actual == 'denied' else 'FN') if expected == 'denied' else ('FP' if actual == 'denied' else 'TN')] += 1
    return dict(counts)
