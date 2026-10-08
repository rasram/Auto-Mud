"""Run frozen A/B evaluation against the held-out attack/control matrix."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ml.training.external_eval import evaluate_external_ab

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('catalog','training-catalog','checkpoint','out'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--device',default='cuda')
    args=parser.parse_args()
    evaluate_external_ab(args.catalog,args.training_catalog,args.checkpoint,args.out,args.device)

if __name__=='__main__':
    main()
