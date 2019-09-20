# NB-Classify (SEAL 3.3.1)
NB-Classify (SEAL 3.3.1) library enables outsourcing of data classification tasks to a cloud server without decryption of data by using FHE to allow secure computation.
The library is implemented using the CKKS scheme within SEAL 3.3.1. All computations are performed over real numbers with precision of 60-bits.
The library also provides a program for training your classification model and writing it out to the required format for the program.


# How to build
1. Use the provided Dockerfile to create the necessary environment for running SEAL.
2. Run the following commands at the root of NB-Classify library to build the library.
    ```terminal
    $ cmake .
    $ make
    ```

# How to run
0. Make a directory `datasets` and put all the necessary files in the directory. Refer to "Format of data sets and other files" at `../README.md`.
1. Setup FHE by generating the keys by running the following commands 
    ```terminal
    $ mkdir keys
    $ bin/setup
    ```
2. Encrypt the trained classification model by running the following commands, then input the name of the data set that you want to encrypt.
    ```terminal
    $ mkdir model
    $ bin/encryptModel
    ```
    
3. To perform classification, first run `mkdir results` then run the following commands depending on your needs. After running the command, input the name of the data set and the number of classes you want to test with.
    1. Classification of single data per query without any optimization:
        `bin/classifySingle`
    2. Classification of single data per query with optimization for each data set:
        `bin/classifySingleOpt`
    3. Classification of multiple data per query:
        `bin/classifyMulti`

# Format of data sets and other files
## List of necessary files
* `$(dataset_name)_info.csv`
* `$(dataset_name)_model.csv`
* `$(dataset_name)_test.csv`
* `$(dataset_name)_train.csv`  (unnecessary if you are going to use your own program for training, given that the model will be formatted in the correct way)

where `$(dataset_name)` is the name of the data set you will later use when running the programming.

A set of sample files is provided in the `datasets` directory. 

You can use `train.py` to train a classification model and write it out to the required format given that the `$(dataset_name)_info.csv` and `$(dataset_name)_train.csv` is formatted correctly.

## Format of $(dataset_name)_info.csv
First row contains names of the class labels. From second row, it contains the names or a value of a feature value for each attribute, one attirubte per row.

Example is given below where N is the number of classes, m is the number of feature values for attribute j.
```
label_0, label_1, ... , label_N
f_0_0, f_1_0, ... , f_m_0
f_0_1, f_1_1, ... , f_m_1
...
f_0_j, f_1_j, ... , f_m_j
```

## Format of $(dataset_name)_model.csv
First row contains the class probabilities. Then, seperated by empty line, it contains series of conditional probabilities where each line contains a conditional probability for each feature value and attribute.
Example is given below where N is the number of classes, m is the number of feature values for attribute j.
```
cl_0, cl_1, ... , cl_N

cp_0_0_0, cp_0_1_0, ... , cp_0_m_0
cp_0_0_1, cp_0_1_1, ... , cp_0_m_1
...
cp_0_0_j, cp_0_1_j, ... , cp_0_m_j

cp_1_0_0, cp_1_1_0, ... , cp_1_m_0
cp_1_0_1, cp_1_1_1, ... , cp_1_m_1
...
cp_1_0_j, cp_1_1_j, ... , cp_1_m_j


...


cp_N_0_0, cp_N_1_0, ... , cp_N_m_0
cp_N_0_1, cp_N_1_1, ... , cp_N_m_1
...
cp_N_0_j, cp_N_1_j, ... , cp_N_m_j
```

## Format of $(dataset_name)_test.csv and $(dataset_name)_train.csv
Each line contains data for classification where each value is the feature value for an attribute and the last value is the actual label. 
```
f0, f1, ..., fj, label
```

## References
* SEAL: https://github.com/microsoft/SEAL
