from django.urls import path
from . import views

urlpatterns = [
    path('', views.txt_to_image_encrypt, name='hide_msg'),
    path('txt-to-img-de', views.txt_to_image_decrypt, name='show_msg'),
    path('img-to-img-en', views.img_to_img_encrypt, name='hide_img'),
    path('img-to-img-de', views.img_to_img_decrypt, name='show_img'),
    path('text_to_audio-en/', views.txt_to_audio_encrypt, name='text_to_audio'),
    path('text_to_audio_de/', views.txt_to_audio_decrypt, name='text_to_audio_de'),
    
]
