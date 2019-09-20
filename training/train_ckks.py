import csv
import json
import math

def loadCsv(filename):
    lines = csv.reader(open(filename, "r"))
    dataset = list(lines)
    for i in range(len(dataset)):
        dataset [i] = [str(x) for x in dataset[i]]
    return dataset

def categorize_data(data):
    categorized = {}
    for i in data:
        label = i[-1]
        if label not in categorized:
            categorized[label]=[]
        categorized[label].append(i[:-1])
    return categorized

def calc_cond_prob(data):
    data_length = len(data[0])
    cond_prob = []
    for each in data:
        temp = {}
        for item in each:
            if item in temp:
                temp[item] = temp[item] + 1
            else:
                temp[item] = 1
        for item in temp:
            temp[item] = float(temp[item])/data_length
        cond_prob.append(temp)
    return cond_prob

def calc_log_cond_prob(data, attributes):
    data_length = len(data[0])
    cond_prob = []
    c = -math.log(3.7e-4)
    print(c)

    for i in range(len(data)):
        each = data[i]
        temp = {}
        for item in each:
            if item in temp:
                temp[item] = temp[item] + 1
            else:
                temp[item] = 1
        att = attributes[i]
        for value in att:
            if value in temp:
                temp[value] = (math.log(temp[value]/data_length) + c)
            else:
                temp[value] = 0
        cond_prob.append(temp)
    return cond_prob


def calc_model(data, attributes = []):
    cond_prob = {}
    if attributes:
        for i in data: #class
            result = calc_log_cond_prob(list(zip(*data[i])), attributes)
            cond_prob[i] = result
    else:
        for i in data: #class
            result = calc_cond_prob(list(zip(*data[i])))
            cond_prob[i] = result

    return cond_prob


print("Input name of data set")
dataName = input()
filename = 'datasets/' + dataName + '_train.csv'
train = loadCsv(filename)
print('Loaded data file {0} with {1} rows'.format(filename, len(train)))

dataInfoFilename = 'datasets/' + dataName + '_info.csv'
dataInfo = loadCsv(dataInfoFilename)
class_names = dataInfo[0]
attribute_values = dataInfo[1:]
print("Loaded information on data set")

categorized_train = categorize_data(train)
class_prob = {}
for key in categorized_train:
    class_prob[key] = len(categorized_train[key])/len(train)

# Trains a model that is not logged or scaled. For testing performance of regular model
trained_model={}
trained_model['class_prob']=class_prob
trained_model['cond_prob'] = calc_model(categorized_train)
modelFilename = 'datasets/' + dataName + '_model_orig.json'
with open(modelFilename, 'w') as outfile:
    json.dump(trained_model, outfile, indent=4)


# Trains a model that is logged, scaled then represented as integers
ckksModel = {}
ckksClassProb = {}
c = -math.log(3.7e-4)  # Value later used to "lift" the logged probabilities so that they will be positive
for key in class_names:
    temp = len(categorized_train[key])/len(train)
    ckksClassProb[key] = (math.log(temp) + c)
ckksModel['class_prob'] = ckksClassProb
ckksModel['cond_prob'] = calc_model(categorized_train, attribute_values)

# For checking performance and accuracy of the trained model over plaintext
with open('datasets/' + dataName + '_model.json', 'w') as outfile:
    json.dump(ckksModel, outfile, indent=4)

print(ckksModel)

# What will actually be encrypted by FHE
with open('datasets/' + dataName + '_model.csv', 'w') as csvfile:
    f = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)

    f.writerow([ckksModel['class_prob'][i] for i in class_names])
    cond_prob = ckksModel['cond_prob']
    for c in class_names:
        f.writerow([])
        for i in range(len(cond_prob[c])):
            f.writerow([cond_prob[c][i][value] for value in attribute_values[i]])