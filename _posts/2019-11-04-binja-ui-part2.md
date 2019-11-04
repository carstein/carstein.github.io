---
layout: post
title: "Binary Ninja UI Plugin, take 2"
date: 2019-11-04
---

# Recap

We've finished [last part](https://carstein.github.io/2019/10/27/binja-ui-part1.html) with functioning custom `View` of limited usefulness . In second part of this miniseries we will try to focus on next thing. We will implement an actual widgets that present structured data. I don't want to turn this text into a Qt beginners  guide but expect explanation of some of the underlying GUI programming principles. Now, without further delay, let's get our hand dirty.

# Before you code

Before we even begin let me give you some references that might be useful in the future when you are  developing your own Qt code.

- [Qt for Python Tutorial](https://wiki.qt.io/Qt_for_Python_Tutorial:_Data_Visualization_Tool)
- [Qt for Python Documentation](https://doc.qt.io/qtforpython/index.html)

I won't be linking documentation to every widget we will be using but please explore it on your own. At least you will have an idea where to look for things when everything goes south.

# Working Table

Uff, that took some time. Finally, after multiple variations and some fighting I got a working version of the View with a table widget. To save some space I've skipped some of the code we've implemented already in the previous part, but the most important elements are on the listing bellow.

```python
sample_data = [
  ['test1', 1, 5,  0, 0],
  ['test2', 3, 20, 2, 1],
]

class CustomTableModel(QAbstractTableModel):
  def __init__(self, data=None):
    QAbstractTableModel.__init__(self)
    self.load_data(data)

  def load_data(self, data):
    self.function_data = data

    self.column_count = 5
    self.row_count = len(self.function_data)

  def rowCount(self, parent=QModelIndex()):
    return self.row_count

  def columnCount(self, parent=QModelIndex()):
      return self.column_count

  def headerData(self, section, orientation, role):
      if role != Qt.DisplayRole:
          return None
      if orientation == Qt.Horizontal:
          return ("Function name", "Blocks", "Instructions", "Calls", "Xrefs" )[section]

  def data(self, index, role = Qt.DisplayRole):
      column = index.column()
      row = index.row()

      if role == Qt.DisplayRole:
          return self.function_data[row][column]
      elif role == Qt.TextAlignmentRole:
          return Qt.AlignRight
    
      return None

class SampleView(QScrollArea, View):
  def __init__(self, parent, binaryView):
    QScrollArea.__init__(self, parent)
    View.__init__(self)
    
    self.setupView(self)
    self.binaryView = binaryView
    
    # Getting the Model
    model = CustomTableModel(sample_data)
     
    # Actually Qt stuff
    container = QWidget(self)
    layout = QHBoxLayout()
    
    table_view = QTableView()
    table_view.setModel(model)
    
    # QTableView Headers
    horizontal_header = table_view.horizontalHeader()
    horizontal_header.setSectionResizeMode(QHeaderView.ResizeToContents)
    
    layout.addWidget(table_view)
    container.setLayout(layout)
    
    self.setWidget(table_view)
```

What we are doing here is simply following the [Model/View Programming](https://doc.qt.io/qt-5/model-view-programming.html) pattern. Our model holding the data is implemented as `CustomTableModel` class. It inherits from `QAbstractTableModel` and implements several methods that will tell the *View* a bit more how to display the information this model holds. The most important one is of course `data()`. I believe code is simple enough, so there is no need for deep explanation. One interesting aspect however is that it not only emits pure values, but can also control (via `role`) other aspects of the view (like in example above - text alignment).

Next element of our puzzle is *View* itself, here named `SampleView`. It is responsible for displaying the data coming from our model. We bind it all together by instantiating  `CustomTableModel`and later on passing it table widget via `setModel()` call.  Rest of the code in the example is responsible for creating set of widgets and wiring them together. 

I won't claim I fully understand QT library, rules that govern layout manager and how widgets are placed and what size they assume. It is quite illustrative if you try to run above code. What you will see is the table widget occupying only a fraction of the space available to it (or at least it did for me). It took me a while to find a solution and I'm still not sure if that is the right one. Well, I hope that as my experience with it will grow I find a more elegant one. Anyway, just add one more line of code at the bottom of `__init__()` method.

```python
self.setWidgetResizable(True)
```

The widget does not look pretty but it will do for now. Attempts to beautify the code will come in one of the later parts.

# What's next

With our code growing it's clear that we need to find some more usable examples to continue our series. Instead of trying to find a new problem to solve I've decided to address the old one. Some time ago I wrote a plugin called [Keyhole](https://github.com/carstein/Keyhole) and I've struggled trying to find a suitable way of displaying the results the plugin was providing. I remember promising myself to revisit my code when proper UI API is available. That time for that has come. Not now of course, but in the next installment of the series.
