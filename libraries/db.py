import sys,os
import sqlite3





class apk_db():
    def __init__(self, db_name):
        self.db_name = db_name
        self.connection = sqlite3.connect(db_name)
        self.cursor = self.connection.cursor()
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")       
 
        if not self.cursor.fetchall():
            self.create_db(self.connection)

        
        
        



    def create_db(self,cursor):

        self.cursor.execute("""CREATE TABLE Application(sha256 TEXT, name TEXT, packageName TEXT, versionCode TEXT, 
                        versionName TEXT, minSdkVersion TEXT, targetSdkVersion TEXT, maxSdkVersion TEXT,
                        permissions TEXT, libraries TEXT, debuggable TEXT, allowbackup TEXT, androidManifest TEXT, stringResources TEXT)""")

        self.cursor.execute("""CREATE TABLE Permissions(app_sha256 TEXT, permission TEXT, type TEXT, shortDescription TEXT, fullDescription TEXT)""")

        self.cursor.execute("""CREATE TABLE Activities(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, autoRemoveFromRecents TEXT, 
                        excludeFromRecents TRUE, noHistory TEXT, permission TEXT)""")

        self.cursor.execute("""CREATE TABLE Services(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, foregroundServiceType TEXT, permission TEXT, process TEXT)""")

        self.cursor.execute("""CREATE TABLE Providers(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, grantUriPermissions TEXT, permission TEXT, process TEXT, readPermission TEXT, writePermission TEXT, authorities TEXT)""")

        self.cursor.execute("""CREATE TABLE Receivers(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, permission TEXT, process TEXT)""")
        
        self.cursor.execute("""CREATE TABLE ActivityAlias(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, permission TEXT, targetActivity TEXT)""")

        self.cursor.execute("""CREATE TABLE IntentFilters(app_sha256 TEXT, componentName TEXT, actionList TEXT, categoryList TEXT, dataList TEXT)""")


    def delete_application(self,sha256):
        sql1 = "DELETE FROM Application WHERE sha256 = '{}'".format(sha256)
        sql2 = "DELETE FROM Permissions WHERE app_sha256 = '{}'".format(sha256)
        sql3 = "DELETE FROM Activities WHERE app_sha256 = '{}'".format(sha256)
        sql4 = "DELETE FROM Services WHERE app_sha256 = '{}'".format(sha256)
        sql5 = "DELETE FROM Providers WHERE app_sha256 = '{}'".format(sha256)
        sql6 = "DELETE FROM Receivers WHERE app_sha256 = '{}'".format(sha256)
        sql7 = "DELETE FROM ActivityAlias WHERE app_sha256 = '{}'".format(sha256)
        sql8 = "DELETE FROM IntentFilters WHERE app_sha256 = '{}'".format(sha256)

        self.cursor.execute(sql1)
        self.cursor.execute(sql2)
        self.cursor.execute(sql3)
        self.cursor.execute(sql4)
        self.cursor.execute(sql5)
        self.cursor.execute(sql6)
        self.cursor.execute(sql7)
        self.cursor.execute(sql8)

        self.connection.commit()
        return


    def get_deeplinks(self,sha256):
        sql = """SELECT componentName,dataList from IntentFilters WHERE app_sha256='{}' AND dataList !=''""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()



    def get_intent_filters(self,sha256):
        sql = """SELECT componentName,actionList,categoryList from IntentFilters WHERE app_sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()


    def query_db(self,sql):
        try:
            self.cursor.execute(sql) 

            return self.cursor.fetchall()
        except Exception as e:
            print(e)
            return None


    def get_all_providers(self,sha256):
        sql = """SELECT * from Providers WHERE app_sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()


    def get_all_receivers(self,sha256):
        sql = """SELECT * from Receivers WHERE app_sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()
    
    def get_all_services(self,sha256):
        sql = """SELECT * from Services WHERE app_sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()

    def get_exported_activities(self,sha256):
        sql = """SELECT name from Activities WHERE app_sha256='{}' AND enabled LIKE 'true%' AND exported LIKE 'true%'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()

    def get_all_activities(self,sha256):
        sql = """SELECT * from Activities WHERE app_sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()

    def get_all_alias_activities(self,sha256):
        sql = """SELECT * from ActivityAlias WHERE app_sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()

    def get_all_permissions(self,sha256):
        sql = """SELECT * from Permissions WHERE app_sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()




    def sha256_exists(self,sha256):
        sql = """SELECT name, packageName from Application WHERE sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        if not self.cursor.fetchall():
            return False
        else:
            return True 

    def get_app_info(self,sha256):
        sql = """SELECT * from Application WHERE sha256='{}'""".format(sha256)
        self.cursor.execute(sql) 
        return self.cursor.fetchall()
   




    def update_intent_filters(self,attribs):
        sql = """INSERT INTO IntentFilters(app_sha256, componentName, actionList, categoryList, dataList) values(?,?,?,?,?)"""
        self.execute_update(sql,attribs)


    def update_application(self,attribs):
        sql = """INSERT INTO Application(sha256,name,packageName,versionCode,versionName,minSdkVersion,
        targetSdkVersion,maxSdkVersion,permissions,libraries, debuggable, allowbackup,androidManifest,stringResources) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
        self.execute_update(sql,attribs)

    def update_permissions(self,attribs):
        sql = """INSERT INTO Permissions(app_sha256,permission,type, shortDescription,fullDescription) values(?,?,?,?,?)"""
        self.execute_update(sql,attribs)

    def update_activities(self,attribs):
        sql = """INSERT INTO Activities(app_sha256, name, enabled, exported, autoRemoveFromRecents, 
                        excludeFromRecents, noHistory, permission) values(?,?,?,?,?,?,?,?)"""
        self.execute_update(sql,attribs)
    
    def update_services(self,attribs):
        sql = """INSERT INTO Services(app_sha256, name, enabled, exported, foregroundServiceType, 
                        permission, process) values(?,?,?,?,?,?,?)"""
        self.execute_update(sql,attribs)


    def update_providers(self,attribs):
        sql = """INSERT INTO Providers(app_sha256, name, enabled, exported, grantUriPermissions, 
                        permission, process,readPermission,writePermission,authorities) values(?,?,?,?,?,?,?,?,?,?)"""
        self.execute_update(sql,attribs)

    def update_receivers(self,attribs):
        sql = """INSERT INTO Receivers(app_sha256, name, enabled, exported, permission, process) values(?,?,?,?,?,?)"""
        self.execute_update(sql,attribs)
    
    def update_activity_alias(self,attribs):
        sql = """INSERT INTO ActivityAlias(app_sha256, name, enabled, exported, permission, targetActivity) values(?,?,?,?,?,?)"""
        self.execute_update(sql,attribs)






    def execute_update(self,sql,attribs):
        self.cursor.execute(sql,attribs)
        self.connection.commit()
        return








