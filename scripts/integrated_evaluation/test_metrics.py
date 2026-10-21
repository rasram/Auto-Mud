import unittest
from metrics import detection, permission_oracle, policy_confusion


class MetricsTests(unittest.TestCase):
    def test_unavailable_positive_reduces_population_recall(self):
        result = detection([{'label': 1, 'flag': True}, {'label': 1, 'flag': None}, {'label': 0, 'flag': False}, {'label': 0, 'flag': None}])
        self.assertEqual(result['population_recall'], .5)
        self.assertEqual(result['coverage'], .5)
        self.assertEqual(result['TN'], 1)
        self.assertEqual(result['population_f1'], 2 / 3)

    def test_undefined_positive_metrics_are_not_perfect(self):
        result = detection([{'label': 0, 'flag': False}])
        self.assertIsNone(result['precision'])
        self.assertIsNone(result['population_recall'])

    def test_each_confusion_cell_and_ineligible(self):
        result = detection([{'label': label, 'flag': flag} for label in [0, 1] for flag in [False, True]] + [{'label': 1, 'flag': True, 'eligible': False}])
        self.assertEqual([result[k] for k in ['TP', 'FP', 'TN', 'FN']], [1, 1, 1, 1])
        self.assertEqual(result['population'], 4)

    def test_rule_direction_and_service_are_not_interchangeable(self):
        mapping = {'10.0.0.11': 'echo', '10.0.0.20': 'hub'}
        rules = {('echo', 'hub', 'tcp', 8080)}
        row = {'orig_h': '10.0.0.11', 'resp_h': '10.0.0.20', 'proto': 'tcp', 'resp_p': 8080}
        self.assertEqual(permission_oracle(row, mapping, rules), 'allowed')
        self.assertEqual(permission_oracle({**row, 'resp_p': 80}, mapping, rules), 'denied')
        self.assertEqual(permission_oracle({**row, 'resp_h': '203.0.113.1'}, mapping, rules), 'unsupported_external_policy')

    def test_unknown_denial_is_not_a_true_negative(self):
        result = policy_confusion([{'expected': 'denied', 'actual': 'unknown_device'}, {'expected': 'allowed', 'actual': 'denied'}])
        self.assertEqual(result['unavailable_forbidden'], 1)
        self.assertEqual(result['FP'], 1)
        self.assertNotIn('TN', result)


if __name__ == '__main__':
    unittest.main()
