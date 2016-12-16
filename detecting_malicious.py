from pprint import pprint as pp
from sklearn import tree
import matplotlib.pyplot as plt
import numpy as np
import sys

total_attribute = 532


def obtain_data_set(filename):
    """Separates each row of a file into a comma-separated nested list, split by spaces.

    :param filename: filename to locate
    :return: list of broken-down file
    """
    with open(filename, mode='rt', encoding='utf-8') as file:
        return [(''.join(line.strip())).split() for line in file]


def remove_duplicate_software(data_set, file_label):
    """Checks data set for duplicate rows and reports the row and data set deleted from.

    :param data_set: data set to detect duplicates
    :param file_label: string-formatted filename searched
    :return: duplicate-free list
    """
    current_index = 0
    for row in data_set:
        # index() provides first instance within list
        if data_set.index(row) != current_index:
            data_set.remove(row)
            print("Removed Row " + str(current_index + 1) + " From " + file_label + "!!")
        current_index += 1
    return data_set


def categorize_software_data(data_set):
    """Divides attribute counter between non-malicious and malicious software.
    List Syntax: [ATTRIBUTE NUMBER, NON-MAL COUNTER, MAL COUNTER]

    :param data_set: data set to traverse attributes
    :return: separated attribute-counter list
    """
    data_list = [['Type', 0, 0]] + [[number, 0, 0] for number in range(1, total_attribute)]

    # differentiates using '+1' (non-malicious) and '-1' (malicious) software indicators
    for row in data_set:
        if '+1' in row[0]:
            data_list[0][1] += 1
            for attribute in row[1:-1]:
                data_list[int(attribute[:-2])][1] += 1
        elif '-1' in row[0]:
            data_list[0][2] += 1
            for attribute in row[1:-1]:
                data_list[int(attribute[:-2])][2] += 1
    return data_list


def filter_meaningful_attribute(data_list):
    """Applies a threshold to maximize results using only the most significant attributes.
    Calculations represented by an attribute to software (non-malicious/malicious) percentage.

    :param data_list: data list to apply filter
    :return: percentile list of desirable attribute
    """
    # filters attributes predominantly non-malicious or malicious (with a 5% threshold)
    for attribute in data_list[1:]:
        to_remove = True
        if ((attribute[1] / data_list[0][1]) > 0.05 > (attribute[2] / data_list[0][2])) \
                or ((attribute[1] / data_list[0][1]) < 0.05 < (attribute[2] / data_list[0][2])):
            to_remove = False

        # filters attributes with a <80% non-malicious-to-malicious ratio threshold
        if -0.8 < (attribute[1] / data_list[0][1]) - \
                (attribute[2] / data_list[0][2]) < 0.8 \
                and to_remove is True:
            data_list.remove(attribute)
        else:
            attribute[1] /= data_list[0][1]
            attribute[2] /= data_list[0][2]
    return data_list


def predict_malicious_percentage(training_data, testing_data_set):
    """Calculates the average non-malicious and malicious percentages for a set of attributes using
    specially-picked *useful* training attributes. Used for self-defined algorithm.
    List Syntax: [SOFTWARE NUMBER, NON-MAL PERCENT, MAL PERCENT]

    :param training_data: filtered percentages of attributes
    :param testing_data_set: software attribute list to predict
    :return: non-malicious/malicious probability percentages
    """
    prediction = [['Prediction']] + [[number, 0, 0] for number in range(1, len(testing_data_set) + 1)]
    for row in testing_data_set:
        attribute_present = 0
        for training_attribute in training_data:

            # if attribute present, add non-mal/mal percentages separately
            for attribute in row:
                if training_attribute[0] == int(attribute[:-2]):
                    prediction[testing_data_set.index(row) + 1][1] += training_attribute[1]
                    prediction[testing_data_set.index(row) + 1][2] += training_attribute[2]
                    attribute_present += 1
                    break
        prediction[testing_data_set.index(row) + 1][1] /= attribute_present
        prediction[testing_data_set.index(row) + 1][2] /= attribute_present
    return prediction


def self_defined_algorithm(training_data, testing_data_set):
    """Self-defined algorithm predicts software as non-malicious or malicious. Incorporates
    attribute percentages from training software to determine likelihood of each type.

    :param training_data: filtered percentages of attributes
    :param testing_data_set: software attribute list to predict
    """
    prediction = predict_malicious_percentage(training_data, testing_data_set)

    # either displays larger percentage or percentage ratio, negative for malicious prediction
    ratio = True
    for item in prediction[1:]:
        if ratio is False:
            if item[1] > item[2]:
                item.remove(item[2])
            else:
                item[2] *= -1
                item.remove(item[1])
        else:
            item[1] -= item[2]
            item.remove(item[2])

    # creates a bar plot of the predicted results
    # x = np.array([software[0] for software in prediction[1:]])
    # y = np.array([percent[1] for percent in prediction[1:]])
    # plt.title('Predicted Malicious Ratio Percentage Results of Software')
    # plt.xlabel('Tested Software')
    # plt.ylabel('Malicious Ratio Percentage')
    # plt.axis([0, len(prediction), -1.1, 1.1])
    # plt.xticks(x, rotation=55)
    # plt.yticks(np.arange(-1.1, 1.1, 0.1))
    # plt.bar(x, y, width=0.35, color='c')
    # plt.show()


def identify_attribute_existence(data_set, training=True):
    attribute_existence = []
    attribute_indicator = []

    for row in data_set:
        if training is True:
            if '+1' in row[0]:
                attribute_indicator.append(1)
            elif '-1' in row[0]:
                attribute_indicator.append(-1)
            row.remove(row[0])
            row.remove(row[-1])

        attribute_existence.append([])
        for number in range(1, total_attribute):
            is_added = False
            for attribute in row:
                if number == int(attribute[:-2]):
                    attribute_existence[len(attribute_existence) - 1].append(1)
                    is_added = True
                    break

            # appends '0' for non-existent attributes in software
            if is_added is False:
                attribute_existence[len(attribute_existence) - 1].append(0)
    return attribute_existence, attribute_indicator


def decision_tree_algorithm(training_data_set, testing_data_set):
    training_attribute, training_indicator = identify_attribute_existence(training_data_set)
    testing_attribute, _ = identify_attribute_existence(testing_data_set, training=False)

    dtr_x = tree.DecisionTreeRegressor()
    dtr_x.fit(training_attribute, training_indicator)

    # dtr_y = dtr_x.predict(testing_attribute)
    # x_test = np.arange(1, len(testing_data_set) + 1)
    # plt.figure()
    # plt.scatter(x_test, dtr_y, color='c')
    # plt.xlabel('data')
    # plt.ylabel('target')
    # plt.title("Decision Tree Regression")
    # plt.legend()
    # plt.show()


def main(training_file, testing_file):
    training_data_set = remove_duplicate_software(obtain_data_set(training_file), 'Training')
    training_data = filter_meaningful_attribute(categorize_software_data(training_data_set))
    testing_data_set = remove_duplicate_software(obtain_data_set(testing_file), 'Testing')

    self_defined_algorithm(training_data[1:], testing_data_set)
    # decision_tree_algorithm(training_data_set, testing_data_set)

    # creates a bar plot counter of desired attributes, separated by non-malicious/malicious
    # attribute_range = np.arange(1, len(training_data))  # displays filtered list of attributes
    # x = np.array([attribute[0] for attribute in training_data])
    # y_non = np.array([non_count[1] for non_count in training_data])
    # y_mal = np.array([mal_count[2] for mal_count in training_data])
    # plt.title('Filtered Non-Malicious and Malicious Software Attribute Percentage Counter')
    # plt.xlabel('Attribute Number')
    # plt.ylabel('Software Percentage Counter')
    # plt.axis([0, len(training_data), 0, 1.1])
    # plt.xticks(attribute_range, x, rotation=55)
    # plt.yticks(np.arange(0, 1.1, 0.1))
    # plt.bar(attribute_range - 0.35, y_non, width=0.35, color='c', label='Non-Malicious')
    # plt.bar(attribute_range, y_mal, width=0.35, color='g', label='Malicious')
    # plt.legend()
    # plt.show()


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
