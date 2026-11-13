"""Independent matching tests; no PCAP generation or research scoring."""
import importlib.util
import itertools
from pathlib import Path
import random
import unittest

path=Path(__file__).resolve().parent/'research/v2/adapters/matching.py'
spec=importlib.util.spec_from_file_location('independent_matching',path)
matching=importlib.util.module_from_spec(spec)
spec.loader.exec_module(matching)
match=matching.match_candidates


def brute_force(episodes,alerts,edges):
    best=None
    result=None
    for n in range(min(len(episodes),len(alerts))+1):
        for chosen in itertools.combinations(edges,n):
            if len({e for e,_,_ in chosen})!=n or len({a for _,a,_ in chosen})!=n:
                continue
            pairs=sorted((e,a) for e,a,_ in chosen)
            key=(-n,sum(d for _,_,d in chosen),pairs)
            if best is None or key<best:
                best,result=key,pairs
    return result


class MatchingTests(unittest.TestCase):
    def test_empty_graph(self):
        self.assertEqual(match([],[],[])['pairs'],[])
        result=match(['e'],['a'],[])
        self.assertEqual(result['unmatched_episodes'],['e'])
        self.assertEqual(result['unmatched_alerts'],['a'])

    def test_cardinality_beats_greedy_distance(self):
        result=match(['e1','e2'],['a1','a2'],[('e1','a1',0),('e1','a2',100),('e2','a1',1)])
        self.assertEqual(result['pairs'],[('e1','a2'),('e2','a1')])
        self.assertEqual(result['total_distance_ns'],101)

    def test_minimum_distance_at_equal_cardinality(self):
        result=match(['e1','e2'],['a1','a2'],[('e1','a1',100),('e1','a2',1),('e2','a1',2),('e2','a2',100)])
        self.assertEqual(result['pairs'],[('e1','a2'),('e2','a1')])
        self.assertEqual(result['total_distance_ns'],3)

    def test_exact_lexicographic_tie(self):
        edges=[(e,a,0) for e in ['e1','e2'] for a in ['a1','a2']]
        self.assertEqual(match(['e2','e1'],['a2','a1'],reversed(edges))['pairs'],[('e1','a1'),('e2','a2')])

    def test_single_aggregate_alert_matches_at_most_one_episode(self):
        result=match(['e1','e2'],['aggregate'],[('e1','aggregate',0),('e2','aggregate',0)])
        self.assertEqual(result['cardinality'],1)
        self.assertEqual(result['unmatched_episodes'],['e2'])

    def test_duplicate_alert_remains_unmatched(self):
        result=match(['e'],['a1','a2'],[('e','a1',0),('e','a2',0)])
        self.assertEqual(result['pairs'],[('e','a1')])
        self.assertEqual(result['unmatched_alerts'],['a2'])

    def test_disconnected_components(self):
        result=match(['e1','e2','e3'],['a1','a2','a3'],[('e1','a1',4),('e3','a3',0)])
        self.assertEqual(result['pairs'],[('e1','a1'),('e3','a3')])
        self.assertEqual(result['unmatched_episodes'],['e2'])
        self.assertEqual(result['unmatched_alerts'],['a2'])

    def test_nanosecond_not_float_distance(self):
        self.assertEqual(match(['e'],['a'],[('e','a',10**30)])['total_distance_ns'],10**30)
        for bad in [0.0,1.5,True,-1,'1']:
            with self.subTest(bad=bad),self.assertRaises(ValueError):match(['e'],['a'],[('e','a',bad)])

    def test_unknown_ids_or_duplicate_edges_fail(self):
        for edges in [[('missing','a',0)],[('e','missing',0)],[('e','a',0),('e','a',1)]]:
            with self.subTest(edges=edges),self.assertRaises(ValueError):match(['e'],['a'],edges)

    def test_invalid_ids_fail(self):
        for episodes,alerts in [(['e','e'],['a']),(['e'],['a','a']),([''],['a']),([1],['a']),(['e'],[''])]:
            with self.subTest(episodes=episodes,alerts=alerts),self.assertRaises(ValueError):match(episodes,alerts,[])

    def test_explicit_limits_not_partial_results(self):
        with self.assertRaises(ValueError):match(['e'],['a'],[],max_nodes=3)
        with self.assertRaises(ValueError):match(['e'],['a'],[('e','a',0)],max_edges=0)
        with self.assertRaises(ValueError):match([],[],[],max_edges=-1)

    def test_all_three_by_three_zero_one_distance_graphs(self):
        episodes=['e0','e1','e2'];alerts=['a0','a1','a2']
        pairs=list(itertools.product(episodes,alerts))
        # Every edge is absent, distance 0 or distance 1: 3**9 = 19,683 graphs.
        for codes in itertools.product(range(3),repeat=9):
            edges=[(e,a,c-1) for (e,a),c in zip(pairs,codes) if c]
            self.assertEqual(match(episodes,alerts,edges)['pairs'],
                             brute_force(episodes,alerts,edges),msg=str(codes))

    def test_randomized_matches_exhaustive_oracle(self):
        rng=random.Random(20261113)
        for i in range(250):
            episodes=['e%d'%n for n in range(rng.randrange(1,5))]
            alerts=['a%d'%n for n in range(rng.randrange(1,5))]
            edges=[(e,a,rng.randrange(5)) for e in episodes for a in alerts if rng.random()<0.6]
            expected=brute_force(episodes,alerts,edges)
            rng.shuffle(episodes);rng.shuffle(alerts);rng.shuffle(edges)
            with self.subTest(graph=i):
                actual=match(episodes,alerts,edges)
                self.assertEqual(actual['pairs'],expected)
                self.assertEqual(actual['cardinality'],len(expected))


if __name__=='__main__':
    unittest.main()
