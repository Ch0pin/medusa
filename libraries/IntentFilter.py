class IntentFilter:

    actionList = []
    categoryList = []
    dataList = []
    componentName = ''

    def __init__(self):
        self.actionList = []
        self.categoryList = []
        self.dataList = []

    def addAction(self,action):
        self.actionList.append(action)

    def addCategory(self,category):
        self.categoryList.append(category)

    def addData(self,data):
        self.dataList.append(data)

    def getActionList(self):
        return self.actionList

    def getCategoryList(self):
        return self.categoryList

    def getDataList(self):
        return self.dataList