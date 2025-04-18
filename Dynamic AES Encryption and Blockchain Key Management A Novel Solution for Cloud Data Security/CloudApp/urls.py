from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
			path("Login.html", views.Login, name="Login"),
			path("LoginAction", views.LoginAction, name="LoginAction"),
			path("Signup.html", views.Signup, name="Signup"),
			path("SignupAction", views.SignupAction, name="SignupAction"),	    
			path("UploadFile.html", views.UploadFile, name="UploadFile"),
			path("UploadFileAction", views.UploadFileAction, name="UploadFileAction"),	  
			path("DownloadFile", views.DownloadFile, name="DownloadFile"),
			path("DownloadFileDataRequest", views.DownloadFileDataRequest, name="DownloadFileDataRequest"),	
			path("Graph", views.Graph, name="Graph"),
]