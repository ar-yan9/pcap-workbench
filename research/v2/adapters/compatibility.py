"""Compatible-edge construction between label episodes and engine predictions.

Implements the preregistered rules of research/v2/evaluator-contract.md:
identity (capture + scanner), direction/family and target/group gates decide
WHETHER an episode-alert pair may match; only then does integer time distance
feed the exact matcher as its tie-break objective. Timing never creates an
edge, and ground truth never supplies identity evidence an engine did not emit.

Timing classes (contract v0.1): 'within' when the alert event time lies in the
label interval, 'delayed' when after it (allowed: Zeek emits aggregate notices
at threshold crossing or offline EOF flush, so notice.ts is not a decision
time), 'early' when before it (rejected: an alert cannot be caused by probes
that had not happened). Engine-unsupported classes (udp/icmp/ip/distributed/
open-port/protocol directions) produce no candidates and are recorded as
unmatched with reasons. Every candidate and every near-miss reject is kept
auditable; far-miss gate failures are counted per alert, not enumerated.
"""

_LABEL_DIRECTIONS = ('vertical', 'horizontal')

# Prediction directions eligible as candidates for label episodes, and the
# class label recorded on the edge. Anything absent is out of supported scope.
_CANDIDATE_DIRECTIONS = {
    'vertical': 'engine-direction',
    'horizontal': 'engine-direction',
    'random': 'random-aggregate',
}


class CompatibilityError(ValueError):
    """Raised on malformed episode or prediction records."""


def _require(record, keys, kind, identifier):
    missing = [key for key in keys if key not in record]
    if missing:
        raise CompatibilityError('%s %s missing keys %s' % (kind, identifier, ','.join(missing)))


def validate_episode(episode):
    _require(episode, ('episode_id', 'capture_id', 'scanner', 'intent',
                       'first_probe_ns', 'last_probe_ns'), 'episode', episode.get('episode_id'))
    target = episode.get('target')
    target_port = episode.get('target_port')
    if (target is None) == (target_port is None):
        raise CompatibilityError('episode %s must set exactly one of target/target_port'
                                 % episode['episode_id'])
    direction = 'vertical' if target is not None else 'horizontal'
    if direction == 'horizontal' and type(target_port) is not int:
        raise CompatibilityError('episode %s target_port must be an int' % episode['episode_id'])
    first = episode['first_probe_ns']
    last = episode['last_probe_ns']
    if type(first) is not int or type(last) is not int or last < first:
        raise CompatibilityError('episode %s has an invalid probe interval' % episode['episode_id'])
    if episode['intent'] not in ('attack', 'benign', 'ambiguous'):
        raise CompatibilityError('episode %s has unknown intent %r'
                                 % (episode['episode_id'], episode['intent']))
    return direction


def validate_prediction(prediction):
    _require(prediction, ('alert_id', 'capture_id', 'scanner', 'direction',
                          'event_time_ns', 'family'), 'prediction', prediction.get('alert_id'))
    if type(prediction['event_time_ns']) is not int:
        raise CompatibilityError('prediction %s event_time_ns must be int ns'
                                 % prediction['alert_id'])


def _timing(event_ns, first_ns, last_ns):
    if first_ns <= event_ns <= last_ns:
        return 'within', 0
    if event_ns > last_ns:
        return 'delayed', event_ns - last_ns
    return 'early', first_ns - event_ns


def _target_ok(direction, episode, prediction):
    """Target/group gate; True/False, or 'unknown-group' for engine-blind groups."""
    if direction == 'vertical':
        if prediction['direction'] == 'random':
            return True
        if prediction.get('target_host') is not None:
            return prediction['target_host'] == episode['target']
        if prediction.get('target_hosts') is not None:
            return episode['target'] in prediction['target_hosts']
        return 'unknown-group'
    if prediction['direction'] == 'random':
        return True
    if prediction.get('target_port') is not None:
        return prediction['target_port'] == episode['target_port']
    if prediction.get('target_ports') is not None:
        return episode['target_port'] in prediction['target_ports']
    return 'unknown-group'


def build_candidates(episodes, predictions):
    """Return {'candidates': [...], 'rejects': [...], 'gate_failures': {...}}.

    candidates: dicts with episode_id, alert_id, distance_ns, timing_class,
    edge_class ('engine-direction' or 'random-aggregate'), intent, direction.
    rejects: near-miss (episode, alert, reason) triples that passed capture and
    scanner gates, so every auditable almost-match is preserved. gate_failures:
    per-alert counts for far misses (wrong capture/scanner), not enumerated.
    """
    episodes = list(episodes)
    predictions = list(predictions)
    ep_direction = {}
    for episode in episodes:
        ep_direction[episode['episode_id']] = validate_episode(episode)
    for prediction in predictions:
        validate_prediction(prediction)

    candidates = []
    rejects = []
    gate_failures = {}
    for prediction in predictions:
        alert_id = prediction['alert_id']
        pred_direction = prediction['direction']
        edge_class = _CANDIDATE_DIRECTIONS.get(pred_direction)
        if edge_class is None:
            gate_failures[alert_id] = {'unsupported-direction': 1}
            continue
        failures = {'capture': 0, 'scanner': 0}
        for episode in episodes:
            episode_id = episode['episode_id']
            if episode['capture_id'] != prediction['capture_id']:
                failures['capture'] += 1
                continue
            if episode['scanner'] != prediction['scanner']:
                failures['scanner'] += 1
                continue
            direction = ep_direction[episode_id]
            if edge_class == 'engine-direction' and direction != pred_direction:
                rejects.append({'episode_id': episode_id, 'alert_id': alert_id,
                                'reason': 'direction-mismatch'})
                continue
            target = _target_ok(direction, episode, prediction)
            if target is False:
                rejects.append({'episode_id': episode_id, 'alert_id': alert_id,
                                'reason': 'target-mismatch'})
                continue
            timing_class, distance_ns = _timing(prediction['event_time_ns'],
                                                episode['first_probe_ns'],
                                                episode['last_probe_ns'])
            if timing_class == 'early':
                rejects.append({'episode_id': episode_id, 'alert_id': alert_id,
                                'reason': 'alert-before-episode'})
                continue
            candidates.append({
                'episode_id': episode_id,
                'alert_id': alert_id,
                'distance_ns': distance_ns,
                'timing_class': timing_class,
                'edge_class': edge_class,
                'group_evidence': ('engine-reported' if target is True else 'unknown-group'),
                'intent': episode['intent'],
                'direction': direction,
            })
        gate_failures[alert_id] = failures
    return {'candidates': candidates, 'rejects': rejects, 'gate_failures': gate_failures}


def matching_input(episodes, predictions, candidates):
    """Project candidates into matching.py's (episode_ids, alert_ids, edges)."""
    episode_ids = [episode['episode_id'] for episode in episodes]
    alert_ids = [prediction['alert_id'] for prediction in predictions]
    edges = [(candidate['episode_id'], candidate['alert_id'], candidate['distance_ns'])
             for candidate in candidates]
    return episode_ids, alert_ids, edges
