import collections
import numpy as np
import pandas as pd
from pylab import *
import matplotlib.pyplot as plt
import csv
import xlwt
import xlrd
import xlsxwriter
import regex as re
import os
from csv import reader
from random import seed
from random import randrange
import sys
import apache_log_parser
from PySide.QtCore import *
from PySide.QtGui import *
from sklearn.naive_bayes import GaussianNB
from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import KFold
from sklearn.metrics import accuracy_score

__title__="Network Forensic Analysis"

class Dialog(QDialog):
    def __init__(self, parent=None):
        super(Dialog, self).__init__(parent)
        self.resize(1000,400)
        self.setWindowTitle(__title__)
        label = QLabel("""<font bold size=8>Network Forensic analysis API, developed using Python and Machine Learning .</font>""")
        openfile = QPushButton("Upload")
        openfile.setFixedSize(100,20)
        analysis = QPushButton("Analysis")
        analysis.setFixedSize(100, 20)
        self.browser = QTextBrowser()
        dial = QGridLayout()
        dial.addWidget(label,0,0,Qt.AlignCenter)
        dial.addWidget(openfile,1,0,Qt.AlignCenter)
        dial.addWidget(self.browser, 2, 0)
        dial.addWidget(analysis,3,0,Qt.AlignCenter)
        self.setLayout(dial)
        self.connect(openfile, SIGNAL("clicked()"), self.open)
        self.connect(analysis,SIGNAL("clicked()"),self.mlanalysis)

    def open(self):
        dir = "."
        fileObj = QFileDialog.getOpenFileName(self,"Open File",dir=dir,filter="Text files (*.txt)")
        fileName = fileObj[0]
        file = open(fileName, 'r')
        read = file.read()
        file.close()
        self.logTOexcel(fileName)
        self.connect(self.browser,SIGNAL("returnPressed"),self.browser.append(read))

    def logTOexcel(self,val):
        inputfilename = os.path.join(val) # Look for input file in same location as script file
        basefilename = os.path.basename(inputfilename) # Strip off the path
        basefilename_noext = os.path.splitext(basefilename)[0]  # Strip off the extension
        targetoutputpath = os.path.dirname(inputfilename)  # Get the path of the input file as the target output path
        outputfilename = os.path.join(targetoutputpath, basefilename_noext + '.xls') # Generate the output filename
        workbook = xlwt.Workbook() # Create a workbook object
        worksheet = workbook.add_sheet(basefilename_noext, cell_overwrite_ok=True) # Add a sheet object
        datareader = csv.reader(open(inputfilename, 'r'),
                                delimiter=' ', quotechar='"') # Get a CSV reader object set up for reading the input file with tab delimiters
        for rowno, row in enumerate(datareader):         # Process the file and output to Excel sheet
            for colno, colitem in enumerate(row):
                worksheet.write(rowno, colno, colitem)
        workbook.save(outputfilename) # Write the output file.

    def mlanalysis(self):
         dialog1 = AnDialog()
         dialog1.exec_()


class AnDialog(QDialog):

    def __init__(self, parent=None):
        super(AnDialog, self).__init__(parent)
        self.resize(400,100)
        self.setWindowTitle(__title__)
        btn0 = QPushButton("Upload")
        btn4 = QPushButton("Report")
        btn1 = QPushButton("Bar Chart")
        btn2 = QPushButton("Pie Chart")
        btn3 = QPushButton("Machine Learning")

        self.dail = QGridLayout()
        self.dail.setSpacing(10)

        self.dail.addWidget(btn0)
        self.dail.addWidget(btn4)
        self.dail.addWidget(btn1)
        self.dail.addWidget(btn2)
        self.dail.addWidget(btn3)
        self.setLayout(self.dail)
        self.connect(btn0, SIGNAL("clicked()"), self.read)
        self.connect(btn1, SIGNAL("clicked()"), self.barchart)
        self.connect(btn2, SIGNAL("clicked()"), self.piechart)
        self.connect(btn4, SIGNAL("clicked()"), self.report)
        self.connect(btn3, SIGNAL("clicked()"), self.machine)

    def read(self):
        dir = "."
        fileObj = QFileDialog.getOpenFileName(self, "Open File", dir=dir, filter="All files (*.*)")
        fileName = fileObj[0]
        workbook = xlrd.open_workbook(fileName)
        sheets = workbook.sheet_names()
        required_data = []
        rowdata3 = []
        finaldata = []

        for sheet_name in sheets:
            sh = workbook.sheet_by_name(sheet_name)
        for rownum in range(sh.nrows):
            row_valaues = sh.row_values(rownum)
            required_data.append((row_valaues[0], row_valaues[3], row_valaues[5], row_valaues[6], row_valaues[7]))
        for rownum in range(sh.nrows):
            rowdata3.append((re.sub(r"[\[]", "", required_data[rownum][1])).split(':', 1))
            finaldata.append((required_data[rownum][0], rowdata3[rownum][0], rowdata3[rownum][1],
                              required_data[rownum][2], required_data[rownum][3], required_data[rownum][4]))
        workbook1 = xlwt.Workbook()
        worksheet1 = workbook1.add_sheet("access_log2", cell_overwrite_ok=True)
        basefilename = os.path.basename(fileName)
        basefilename_noext = os.path.splitext(basefilename)[0]
        targetoutputpath = os.path.dirname(fileName)
        outputfilename = os.path.join(targetoutputpath, "ForReport_"+basefilename_noext + '.xls')
        rows = sh.nrows
        colms = sh.ncols
        self.tablewidget = QTableWidget(rows, colms)
        self.resize(700, 500)
        self.tablewidget.setHorizontalHeaderLabels(['IP', 'Date', 'Time', 'URL', 'Server Respose', 'Download',' ', ' '])
        for rownum in range(rows):
            for colnum in range(0, 6):
                worksheet1.write(rownum, colnum, finaldata[rownum][colnum])
                item = QTableWidgetItem(finaldata[rownum][colnum]) # Write the output to TableWidget
                self.tablewidget.setItem(rownum, colnum, item)
        workbook1.save(outputfilename)
        self.dail.addWidget(self.tablewidget)
        self.setLayout(self.dail)



    def openfileforanalysis(self):
        dir = "."
        fileObj = QFileDialog.getOpenFileName(self, "Open File", dir=dir, filter="All files (*.*)")
        fileName = fileObj[0]
        workbook = xlrd.open_workbook(fileName)
        sheets = workbook.sheet_names()
        ip = []
        for sheet_name in sheets:
            sh = workbook.sheet_by_name(sheet_name)
        for rownum in range(sh.nrows):
            row_valaues = sh.row_values(rownum)
            ip.append(row_valaues[0])
        counter = collections.Counter(ip)
        mal_list = []
        mal_ip = []
        mal_freq = []
        for i in counter.items():
            if i[1] > 15:
                mal_list.append(i)
            else:
                continue
        for i in mal_list:
            mal_ip.append(i[0])
            mal_freq.append(i[1])
        return mal_ip,mal_freq,mal_list

    def barchart(self):
        mal_ip, mal_freq,mal_list = self.openfileforanalysis()
        label = mal_ip
        pos = np.arange(len(mal_ip))
        width = 1.0  # gives histogram aspect to the bar diagram
        ax = plt.axes()
        ax.set_xticks(pos + (width / 2))
        ax.set_xticklabels(label, rotation='vertical')
        plt.bar(pos, mal_freq, width, color='b')
        plt.show()

    def piechart(self):
        mal_ip,mal_freq,mal_list = self.openfileforanalysis()
        figure(1, figsize=(6, 6))
        ax = axes([0.1, 0.1, 0.8, 0.8])
        labels = mal_ip
        fracs = mal_freq
        pie(fracs, labels=labels,
            autopct='%1.1f%%', shadow=True, startangle=90)
        title('Malicious IPs', bbox={'facecolor': '0.8', 'pad': 5})
        show()

    def report(self):
        mal_ip, mal_freq, mal_list = self.openfileforanalysis()
        df = pd.DataFrame(mal_list)
        self.datatable = QTableWidget(parent=self)
        self.datatable.setColumnCount(len(df.columns))
        self.datatable.setRowCount(len(df.index))
        self.datatable.setHorizontalHeaderLabels(['IP', 'Frequency'])
        for i in range(len(df.index)):
            for j in range(len(df.columns)):
                self.datatable.setItem(i, j, QTableWidgetItem(str(df.iat[i, j])))
        self.dail.addWidget(self.datatable)
        self.setLayout(self.dail)

    def testandtrain(self):
        dir = "."
        fileObj = QFileDialog.getOpenFileName(self, "Open File", dir=dir, filter="All files (*.*)")
        fileName = fileObj[0]
        workbook = xlrd.open_workbook(fileName)
        sheets = workbook.sheet_names()
        required_data = []
        rowdata3 = []
        finaldata = []
        classlable = []
        for sheet_name in sheets:
            sh = workbook.sheet_by_name(sheet_name)
        for rownum in range(sh.nrows):
            row_valaues = sh.row_values(rownum)
            required_data.append((row_valaues[0], row_valaues[3], row_valaues[5], row_valaues[6], row_valaues[7]))
        for rownum in range(sh.nrows):
            # classification on the basis of responce code
            if (int(required_data[rownum][3]) >= 400):
                classlable.append('1')
            else:
                classlable.append('0')
        for rownum in range(sh.nrows):
            rowdata3.append((re.sub(r"[\[]", "", required_data[rownum][1])).split(':', 1))
            finaldata.append((required_data[rownum][0],
                              rowdata3[rownum][0],
                              rowdata3[rownum][1],
                              required_data[rownum][2],
                              required_data[rownum][3],
                              required_data[rownum][4],
                              classlable[rownum]))
        dataframe = pd.DataFrame(finaldata)
        return dataframe

    def machine(self):
        newdata=self.testandtrain()
        dialog2 = Learning(newdata)
        dialog2.exec_()


class Learning(QDialog):
    def __init__(self, newdata,parent=None):
        super(Learning, self).__init__(parent)
        self.new = newdata
        self.setWindowTitle(__title__)
        self.resize(400,100)
        buttn1 = QPushButton("CART")
        buttn2 = QPushButton("KNN")
        buttn3 = QPushButton("Naive Bayes")

        self.dail = QGridLayout()
        self.dail.setSpacing(10)
        self.dail.addWidget(buttn1,1,0)
        self.dail.addWidget(buttn2,2,0)
        self.dail.addWidget(buttn3,3,0)
        self.setLayout(self.dail)
        self.connect(buttn1, SIGNAL("clicked()"), self.cart)
        self.connect(buttn2, SIGNAL("clicked()"), self.knn)
        self.connect(buttn3, SIGNAL("clicked()"), self.navie)

    def cart(self):
        dataframe1 = self.new.replace('-', 0)
        newdata = dataframe1.filter([4, 5, 6], axis=1)
        train = newdata.sample(frac=0.8, random_state=200)
        test = newdata.drop(train.index)
        traindata = pd.DataFrame(train)
        testdata = pd.DataFrame(test)
        x_pre = []
        y_tar = []
        for rownum in range(len(traindata)):
            x_pre.append(([int(traindata[4].iloc[rownum]), int(traindata[5].iloc[rownum])]))
            y_tar.append(int(traindata[6].iloc[rownum]))
        x = np.array(x_pre)
        y = np.array(y_tar)
        clf = tree.DecisionTreeClassifier(random_state=0, max_depth=5)
        clf1 = clf.fit(x, y)
        x_test = []
        y_test = []
        for rownum in range(len(testdata)):
            x_test.append(([int(testdata[4].iloc[rownum]), int(testdata[5].iloc[rownum])]))
            y_test.append(int(traindata[6].iloc[rownum]))
        predicted=clf.predict(x_test)
        test_pre = pd.DataFrame(x_test, predicted)
        test_pre.reset_index(level=0, inplace=True)
        scores = cross_val_score(clf1, x, y, scoring='accuracy', cv=5)
        ac =  accuracy_score(y_test,predicted)
        msgBox = QMessageBox()
        msgBox.setWindowTitle(__title__)
        msgBox.setText("Accuracy of CART is : "+unicode(ac)+"\n"+"Do you want to print the predicted data set ?")
        msgBox.addButton(QMessageBox.Yes)
        msgBox.addButton(QMessageBox.No)
        msgBox.setDefaultButton(QMessageBox.No)
        ret = msgBox.exec_()
        if ret == QMessageBox.Yes:
            self.datatable1 = QTableWidget(parent=self)
            self.resize(700, 500)
            self.datatable1.setColumnCount(len(test_pre.columns))
            self.datatable1.setRowCount(len(test_pre.index))
            self.datatable1.setHorizontalHeaderLabels(['Predicted class label','Server Response code','Downloads'])
            for i in range(len(test_pre.index)):
                for j in range(len(test_pre.columns)):
                    self.datatable1.setItem(i, j, QTableWidgetItem(str(test_pre.iat[i, j])))
            self.dail.addWidget(self.datatable1)
            self.setLayout(self.dail)
        else:
            msgBox.close()
    def knn(self):
        dataframe1 = self.new.replace('-', 0)
        newdata = dataframe1.filter([4, 5, 6], axis=1)
        train = newdata.sample(frac=0.8, random_state=200)
        test = newdata.drop(train.index)
        traindata = pd.DataFrame(train)
        testdata = pd.DataFrame(test)
        x_pre = []
        y_tar = []
        for rownum in range(len(traindata)):
            x_pre.append(([int(traindata[4].iloc[rownum]), int(traindata[5].iloc[rownum])]))
            y_tar.append(int(traindata[6].iloc[rownum]))
        x = np.array(x_pre)
        y = np.array(y_tar)
        knn = KNeighborsClassifier(n_neighbors=3)
        knn.fit(x,y)
        x_test = []
        y_test = []
        for rownum in range(len(testdata)):
            x_test.append(([int(testdata[4].iloc[rownum]), int(testdata[5].iloc[rownum])]))
            y_test.append(int(traindata[6].iloc[rownum]))
        pred = knn.predict(x_test)
        test_pre = pd.DataFrame(x_test, pred)
        test_pre.reset_index(level=0, inplace=True)
        ac = accuracy_score(y_test, pred)
        msgBox = QMessageBox()
        msgBox.setWindowTitle(__title__)
        msgBox.setText("Accuracy of KNN is : " + unicode(ac) + "\n" + "Do you want to print the predicted data set ?")
        msgBox.addButton(QMessageBox.Yes)
        msgBox.addButton(QMessageBox.No)
        msgBox.setDefaultButton(QMessageBox.No)
        ret = msgBox.exec_()
        if ret == QMessageBox.Yes:
            self.datatable1 = QTableWidget(parent=self)
            self.resize(700, 500)
            self.datatable1.setColumnCount(len(test_pre.columns))
            self.datatable1.setRowCount(len(test_pre.index))
            self.datatable1.setHorizontalHeaderLabels(['Predicted class label', 'Server Response code', 'Downloads'])
            for i in range(len(test_pre.index)):
                for j in range(len(test_pre.columns)):
                    self.datatable1.setItem(i, j, QTableWidgetItem(str(test_pre.iat[i, j])))
            self.dail.addWidget(self.datatable1)
            self.setLayout(self.dail)
        else:
            msgBox.close()

    def navie(self):
        dataframe1 = self.new.replace('-', 0)
        newdata = dataframe1.filter([4, 5, 6], axis=1)
        train = newdata.sample(frac=0.8, random_state=200)
        test = newdata.drop(train.index)
        traindata = pd.DataFrame(train)
        testdata = pd.DataFrame(test)
        x_pre = []
        y_tar = []
        for rownum in range(len(traindata)):
            x_pre.append(([int(traindata[4].iloc[rownum]), int(traindata[5].iloc[rownum])]))
            y_tar.append(int(traindata[6].iloc[rownum]))
        x = np.array(x_pre)
        y = np.array(y_tar)
        model = GaussianNB()
        # Train the model using the training sets
        model.fit(x, y)
        # Predict Output
        range(len(testdata))
        x_test = []
        y_test = []
        for rownum in range(len(testdata)):
            x_test.append(([int(testdata[4].iloc[rownum]), int(testdata[5].iloc[rownum])]))
            y_test.append(int(traindata[6].iloc[rownum]))
        predicted = model.predict(x_test)
        test_pre = pd.DataFrame(x_test, predicted)
        test_pre.reset_index(level=0, inplace=True)
        ac = accuracy_score(y_test, predicted)
        msgBox = QMessageBox()
        msgBox.setWindowTitle(__title__)
        msgBox.setText("Accuracy of Naive Bayes is : " + unicode(ac) + "\n" + "Do you want to print the predicted data set ?")
        msgBox.addButton(QMessageBox.Yes)
        msgBox.addButton(QMessageBox.No)
        msgBox.setDefaultButton(QMessageBox.No)
        ret = msgBox.exec_()
        if ret == QMessageBox.Yes:
            self.datatable1 = QTableWidget(parent=self)
            self.resize(700, 500)
            self.datatable1.setColumnCount(len(test_pre.columns))
            self.datatable1.setRowCount(len(test_pre.index))
            self.datatable1.setHorizontalHeaderLabels(['Predicted class label', 'Server Response code', 'Downloads'])
            for i in range(len(test_pre.index)):
                for j in range(len(test_pre.columns)):
                    self.datatable1.setItem(i, j, QTableWidgetItem(str(test_pre.iat[i, j])))
            self.dail.addWidget(self.datatable1)
            self.setLayout(self.dail)
        else:
            msgBox.close()


app = QApplication(sys.argv)
form = Dialog()
form.show()
app.exec_()
