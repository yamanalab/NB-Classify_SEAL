#include <string>
#include <vector>
#include "seal/seal.h"
 
using namespace std;
using namespace seal;

struct Model {
  int class_num; //Number of classes
  int feature_num; //Number of features
  vector <int> feature_value_num; //Number of values per feature
  vector <vector <double> > probs;
};

struct Info{
	int class_num;
	int num_features;
	vector <string> class_names;
	vector <vector <string> > attr_values;
};

template <typename T>
void printVector(vector <T>& data){
  for (int i=0; i<data.size(); i++){ cout << data[i] << " "; }
  cout << endl;
}

Model readModel (string, vector <string>, vector <vector <string> >);
void printModel(Model);
Info readInfo(string);

vector <vector <string> > readData(string);
void printAllData(vector <vector <string> >& );
vector <double> parseData(vector <string>, vector <vector <string> >);

vector <long> genPermVec (int);
vector <long> readPermVec (string);

PublicKey loadPK(string);
SecretKey loadSK(string);
GaloisKeys loadGK(string);
RelinKeys loadRK(string);

void writeCtxt(string, Ciphertext);
Ciphertext loadCtxt(string, shared_ptr<SEALContext>);

long numBits(long);
bool curBit(long, long);
void sumAll(Evaluator&, Ciphertext&, GaloisKeys&, long);
