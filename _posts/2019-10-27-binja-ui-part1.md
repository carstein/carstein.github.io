---
layout: post
title: "Binary Ninja UI Plugin, take 1"
date: 2019-10-27
---

# Motivation

Today I've decided to try something new. This time I will be writing those notes as I'm trying to write a binary ninja plugin taking advantage of recent UI API.  That of course means that notes you are reading right now will be bit less polished than usual. I will try to fact check (or at least document check) everything but occasionally you will most likely catch me writing something that makes little sense.

There is a second reason as well. Aren't we all annoyed by all those perfect notes and research papers where everybody has a 20/20 vision and makes no mistakes? What is see in such case is a missed opportunity to learn from someone else mistakes. And believe me, you will most likely learn a lot from my mistakes.

# UI in the past

Binary Ninja 1.2 has just [landed](https://binary.ninja/2019/09/30/1.2-launch.html) in stable channel for everyone to download. Among many important changes is has a new UI API that will enable us to finally write a proper user interface for our plugins. This is not the first time that Binja allow us to create some fancy widgets and windows. There are some ready made components available by importing `interaction` module. It contains several function like for example `binaryninja.interaction.get_address_input` or `binaryninja.interaction.show_html_report` - names are self-explanatory so I'm not going to spend much time writing about it. Worth mentioning was that this module provided you with basic set of widgets but nothing more. It was impossible to style those widgets, modify their behavior or create your own. 

Well, technically there was a way to do it, but it required a bit of hacking and cheating. If you create your own QTWidgets it was possible to attach it to main window, but it wasn't a supported method.

Developers were acutely aware, that sooner or later people will start to complain about such limitations and decided to give us a way better method to build proper GUI. Here comes the `binaryninjaui` module.

# Tools of the trade

Let's set up our scene before we begin. I'll be using Binary Ninja version 1.2.1937-dev and you can test if version you are running has UI API enabled by just running `import binaryninjaui`. If it returns no error, you are good to go.

Now, just importing bunch of stuff from this library and trying to cobble something together might be fairly entertaining but probably won't take us too far. What we need is a good example code that ideally was written by someone at least semi-competent and is known to work and show something up. I think I have perfect candidate - a [snippets](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples/snippets) plugin written by Jordan, a Binja developer himself.

# Make it show up

I begin by reading the snipets plugin code trying to determine what parts we are going to need to implement our simple experiment. To save some space and time I won't be pasting fragments of snippets plugin, but instead, I will just write code myself and test it to make sure it works.

I always start by checking the imports, and oh my, there are a lot of them. The most important ones are those related to `PySide2` library. It looks like a set of bindings for QT libraries to create all the basic widgets and components we are going to display later on. Full disclosure - last GUI application I wrote was probably 10 years ago, during my university years and it was [WxWidgets](https://www.wxwidgets.org/). Still, basic principles behind making GUI (be it QT or GTK) probably haven't changed that much, so I'm staying optimistic.

Next important thing is how to inform Binja about your plugin existence and register yourself as full citizen. In our example script we will find this code at the end, but be careful because snippets plugin is dual use - it can be either run as a standalone app or inside BinaryNinja.

Let's try to stitch something together now.

```python
# Binja UI Plugin take 1

from binaryninjaui import UIAction, UIActionHandler, Menu
from PySide2.QtWidgets import QMessageBox

# Const
action_name = 'Test\\Run Test 1'

class Window(QMessageBox):
  def __init__(self, parent=None):
    super(Window, self).__init__(parent)

    self.setText('Hello Binja UI')


# functions
def launch_plugin(context):
  window = Window()
  window.exec_()


UIAction.registerAction(action_name)
UIActionHandler.globalActions().bindAction(action_name, UIAction(launch_plugin))
Menu.mainMenu('Tools').addAction(action_name, 'show')
```

Whoho, I was able to display something.

Now let's try to analyze what is going on. First we look at lines at the end of the file - here we register our plugin. I'm still now sure if all the steps are needed and what each one means so let's just take it for granted till we have better understanding. Important part however is `UIAction(launch_plugin)` instruction. That ties this part of code with `launch_plugin` function which is responsible for instantiating and showing our widget. Widget itself is nothing fancy and we will work on expanding that in the next part of this series.

Before we congratulate ourselves let's try to do one more thing. Plugin I wan to write will need to operate on `BinaryView` but in the current code there is nothing that would connect those two words together. We need to fix that.

```python
# Binja UI Plugin take 2

from binaryninjaui import UIAction, UIActionHandler, Menu
from PySide2.QtWidgets import QMessageBox

# Const
action_name = 'Test\\Run Test 1'

class Window(QMessageBox):
  def __init__(self, parent=None):
    super(Window, self).__init__(parent)

  def setContext(self, c):
    self.context = c

    self.setText('Hello ' + self.context.binaryView.file.filename)

# functions
def launch_plugin(context):
  window = Window()
  window.setContext(context)
  window.exec_()


UIAction.registerAction(action_name)
UIActionHandler.globalActions().bindAction(action_name, UIAction(launch_plugin))
Menu.mainMenu('Tools').addAction(action_name, 'show')
```

As you can see above launch_plugin function is called with `context`. We just pass it to our widget and extract binaryView out of it. I can't say I like this approach thou. It seems not very elegant - we need to pass it manually, check for errors etc. I haven't tested it yet but it also seems that widget I will create won't be anchored to the main window (or at least I have no idea how to do it).

There must be a better way to do it and after quick google search it seems that a `View` might be something I'm looking for.

# Custom View - take 1

And it looks like that after many iterations we have something that works.

```python
# Binja UI Plugin take 3

# binja stuff
from binaryninja import binaryview
from binaryninjaui import View, ViewType

# binja UI stuff
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QLabel


class SampleView(QScrollArea, View):
  def __init__(self, parent, binaryView):
    QScrollArea.__init__(self, parent)
    
    View.__init__(self)
    View.setBinaryDataNavigable(self, False)
    self.setupView(self)

    self.binaryView = binaryView

    # Actually Qt stuff
    container = QWidget(self)
    layout = QVBoxLayout()
    label = QLabel("Hello " + self.binaryView.file.filename)
    layout.addWidget(label)
    container.setLayout(layout)
    self.setWidget(container)

  def getCurrentOffset(self):
    return 0

  def getData(self):
    return self.binaryView


class SampleViewType(ViewType):
  def __init__(self):
    super(SampleViewType, self).__init__("Sample View", "Sample View")

  def create(self, binaryView, view_frame):
    return SampleView(view_frame, binaryView)

  def getPriority(self, binaryView, filename):
    return 1


ViewType.registerViewType(SampleViewType())
```

It's best to start the analysis from the end. First thing our plugin does is registering itself via `ViewType.registerViewType`. What are we registering is a type of view - this does not have any code responsible for displaying things we might want to display but it acts as some sort of persistence layer of a sort (again, without proper documentation I'm just guessing).  This view type needs to implement two important method - `create()` and `getPriority()`. First one is obvious - it is responsible for creating and *actual* view and the second I have no idea, but if you  miss some mandatory method your plugin won't work and binary ninja window will remain impossible to close.

Last and most important things we need to implement is the `SampleView` where we will display our widgets later on. As previously - there are few mandatory method you need to implement and your plugin won't work without them or will crash when you try to conduct some actions. With my current code I get away with `getData()` and `getCurrentOffset()` but there are few more that I saw in other example. Let's leave them for some other time.

# Closing words

I hope that this short text will help you a bit in your efforts with new binary ninja UI API. You might have noticed that this text lacks a deeper explanation of some of the functions. It pains me as well not to know why certain things are coded this particular way, but I hope that soon we will have better documentation that will give us deeper understanding. Or maybe it's just my unfamiliarity with Qt?

Also you might have noticed that I haven't touched topic how to actually put something on screen and you might wonder why there is a label inside a layout inside a container. I wonder that too, but we will explore this a bit in the second part, where for a change I will try to implement something useful. 

