"""Exact matching primitive for the independent evaluator, not a scorer.

Callers must establish compatible episode/alert edges independently of detector
success. This module does not decide family, identity, timing allowances, labels,
precision or recall. Pending adapters/contract must do that before any study run.
"""


def match_candidates(episode_ids, alert_ids, candidates, max_nodes=256, max_edges=4096):
    """Maximize pairs, minimize total integer distance, then lexicographic pairs.

    candidates: iterable of (episode_id, alert_id, distance_ns). Each edge appears
    at most once. Distances must be nonnegative integers, not floats or bools.
    Capacity limits fail explicitly; no approximate or silently truncated result.
    IDs and output pairs are sorted, so input order cannot choose the outcome.
    """
    episodes, alerts = list(episode_ids), list(alert_ids)
    for name, values in [('episode', episodes), ('alert', alerts)]:
        if any(not isinstance(v,str) or not v for v in values):
            raise ValueError(name+' IDs must be nonempty strings')
        if len(set(values))!=len(values):
            raise ValueError('duplicate '+name+' ID')
    episodes, alerts = sorted(episodes), sorted(alerts)
    if type(max_nodes) is not int or type(max_edges) is not int or max_nodes<2 or max_edges<0:
        raise ValueError('invalid matching resource limits')
    if len(episodes)+len(alerts)+2>max_nodes:
        raise ValueError('matching node limit exceeded')
    ep_index={v:i+1 for i,v in enumerate(episodes)}
    al_index={v:i+1+len(episodes) for i,v in enumerate(alerts)}
    edges=[]
    seen=set()
    for episode,alert,distance in candidates:
        if episode not in ep_index or alert not in al_index:
            raise ValueError('candidate references an unknown ID')
        if type(distance) is not int or distance<0:
            raise ValueError('distance must be nonnegative integer nanoseconds')
        if (episode,alert) in seen:
            raise ValueError('duplicate candidate edge')
        seen.add((episode,alert))
        edges.append((episode,alert,distance))
        if len(edges)>max_edges:
            raise ValueError('matching edge limit exceeded')
    edges.sort()
    size=len(episodes)+len(alerts)+2
    source,sink=0,size-1
    graph=[[] for _ in range(size)]

    def add(start,end,cost):
        forward=[end,len(graph[end]),1,cost]
        reverse=[start,len(graph[start]),0,-cost]
        graph[start].append(forward)
        graph[end].append(reverse)
        return forward

    for episode in episodes:
        add(source,ep_index[episode],0)
    for alert in alerts:
        add(al_index[alert],sink,0)
    # For fixed cardinality k, k*base is constant. Maximizing the binary
    # signature of chosen sorted edges gives the exact lexicographic tie break.
    # Any signature difference is < base, so 1 ns of distance always dominates.
    base=1<<len(edges)
    references=[]
    for rank,(episode,alert,distance) in enumerate(edges):
        tie_cost=base-(1<<(len(edges)-rank-1))
        forward=add(ep_index[episode],al_index[alert],distance*base+tie_cost)
        references.append((episode,alert,distance,forward))
    cardinality=0
    while True:
        distance=[None]*size
        predecessor=[None]*size
        distance[source]=0
        # Residual reverse edges can have negative cost. Bellman-Ford avoids
        # assuming nonnegative costs and is bounded by the explicit graph caps.
        for _ in range(size-1):
            changed=False
            for start in range(size):
                if distance[start] is None:
                    continue
                for idx,edge in enumerate(graph[start]):
                    end,_,capacity,cost=edge
                    proposed=distance[start]+cost
                    if capacity and (distance[end] is None or proposed<distance[end]):
                        distance[end]=proposed
                        predecessor[end]=(start,idx)
                        changed=True
            if not changed:
                break
        if distance[sink] is None:
            break
        end=sink
        while end!=source:
            start,idx=predecessor[end]
            edge=graph[start][idx]
            edge[2]-=1
            graph[end][edge[1]][2]+=1
            end=start
        cardinality+=1
    pairs=[(ep,al) for ep,al,_,edge in references if edge[2]==0]
    cost=sum(d for _,_,d,edge in references if edge[2]==0)
    matched_ep={ep for ep,_ in pairs}
    matched_al={al for _,al in pairs}
    return {'pairs':pairs,'cardinality':cardinality,'total_distance_ns':cost,
            'unmatched_episodes':[ep for ep in episodes if ep not in matched_ep],
            'unmatched_alerts':[al for al in alerts if al not in matched_al],
            'candidate_edges':len(edges)}
