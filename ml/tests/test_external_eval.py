import pytest
from ml.schema import read_json,write_json,file_hash
from ml.smoke import fixtures
from ml.training.external_eval import checked_test_graphs,metrics


def test_external_test_checks_provenance_and_session_separation(tmp_path):
    catalog=fixtures(tmp_path)
    artifact={'catalog_sha256':file_hash(catalog),'smoke':True}
    graphs,provenance=checked_test_graphs(catalog,catalog,artifact)
    assert len(graphs)==20 and len(provenance)==1
    external=read_json(catalog)
    external['partitions']['stage2_train'].append(external['partitions']['stage2_test'][0])
    path=catalog.parent/'overlap.json'
    write_json(path,external)
    with pytest.raises(ValueError,match='test session overlaps'):
        checked_test_graphs(path,catalog,artifact)


def test_external_test_rejects_wrong_training_catalog_and_changed_graphs(tmp_path):
    catalog=fixtures(tmp_path)
    artifact={'catalog_sha256':file_hash(catalog),'smoke':True}
    with pytest.raises(ValueError,match='Training catalog'):
        checked_test_graphs(catalog,catalog,{**artifact,'catalog_sha256':'wrong'})
    rule=read_json(catalog)['partitions']['stage2_test'][0]
    with (catalog.parent/rule['path']).open('a') as f:
        f.write('\n')
    with pytest.raises(ValueError,match='graph file changed'):
        checked_test_graphs(catalog,catalog,artifact)


def test_metrics_distinguish_unscored_positive_windows():
    rows=[{'status':'ok','label':label,'score':score,'flag':flag} for label,score,flag in
          [(1,.9,True),(1,None,None),(0,.8,True),(0,.1,False)]]
    result=metrics(rows,'score','flag')
    assert result['true_positive']==result['false_positive']==result['true_negative']==1
    assert result['support']==3 and result['unscored']==1
    assert result['recall']==1 and result['population_recall']==.5
    assert result['precision']==.5 and result['f1']==pytest.approx(2/3)
    assert result['coverage']==.75
