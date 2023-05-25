from django.shortcuts import render
from django.http import HttpResponse, HttpResponseServerError
from PIL import Image
from PIL.PngImagePlugin import PngInfo
import numpy as np
import math as math
import piexif as piexif
from .stego import Steganography
import wave
import ast
from django.core.mail import send_mail

from .AES import encrypt_message, decrypt_message
from Cryptodome.Random import get_random_bytes

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def text_to_bits(text):
    # convert text to binary format
    bits = bin(int.from_bytes(text.encode(), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def txt_to_image_encrypt(request):
    if request.method == 'POST':
        # Get the image and message from the POST request
        image = request.FILES.get('image')
        message = request.POST.get('message')
        email = request.POST['email']

        encryption_key = get_random_bytes(16)
        message_bytes = message.encode()
        print(len(encryption_key))
        # Encrypt the message
        message = encrypt_message(message_bytes, encryption_key)
        
        try:
        # Open the image and convert it to RGBA mode
            
            img = Image.open(image)
            alpha_img = img.convert("RGBA")  # rgba
            imgnp = np.array(alpha_img)
            x_axis = min(len(imgnp[0]), len(message)*2)
            y_axis = math.ceil(len(message)*2/len(imgnp[0]))
            # print(x_axis, y_axis)
            # print(imgnp[0][0], imgnp[0][1])
            index = 0
            max_message_length = ( len(imgnp[0]) * len(imgnp) * 4) // 8
            if(max_message_length<len(message)*8):
                print("Secret message is too long to embed in image file.")
                return
            for row in range(y_axis):
                for col in range(0, x_axis, 2):
                    # print(row, col)
                    px = [imgnp[row][col], imgnp[row][col+1]]
                    if (index < len(message)):
                        binary = bin(message[index])[2:].zfill(8)
                        
                        
                        # print(binary)
                        for i in range(len(px)):
                            b, g, r, a = px[i]
                            # print(r, g, b, a)
                            b = (b & ~1) | int(binary[0 + (4 * i)])
                            g = (g & ~1) | int(binary[1 + (4 * i)])
                            r = (r & ~1) | int(binary[2 + (4 * i)])
                            a = (a & ~1) | int(binary[3 + (4 * i)])
                            # print("mod", r, g, b, a,binary, index)
                            imgnp[row][col+i] = [b, g, r, a]
                        index += 1

            # Save the modified image
            img = Image.fromarray(imgnp, 'RGBA')
            img.save("Hidden.png")
            imgs= Image.open("Hidden.png")
            metadata = PngInfo()
            metadata.add_text("StrLen", str(len(message)))
            imgs.save("Hidden.png", pnginfo=metadata)
            

            # Send the key discreetly through email
            subject = 'Encryption Key'
            message = f'Please find your encryption key: {encryption_key}'
            send_mail(subject, message, 'your_email_address', [email])

            # Return the modified image as a response
            with open('hidden.png', 'rb') as f:
                response = HttpResponse(f.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="hidden.png"'
                return response

        except Exception as e:
            return HttpResponseServerError(f'Error: {e}')
    return render(request, 'txt-to-image-en.html')

def txt_to_image_decrypt(request):
    if request.method == 'POST':
        # Get the image and message from the POST request
        image = request.FILES.get('image')
        key = request.POST['key']
        
        print(len(key), " HHH ",key)
        try:
            # Open the image and convert it to RGBA mode
            img = Image.open(image)
            alpha_img = img.convert("RGBA")  # rgba
            msgLen = int(img.text['StrLen'])
            imgnp = np.array(alpha_img)

            x_axis = min(len(imgnp[0]), msgLen*2)
            y_axis = math.ceil((msgLen)*2/len(imgnp[0]))
            smsg = ""
            index = 0
            for row in range(y_axis):
                for col in range(0, x_axis, 2):
                    px = [imgnp[row][col], imgnp[row][col+1]]
                    # least significant bit decoding
                    for i in range(len(px)):
                        r, g, b, a = px[i]

                        smsg += str(r & 1)
                        smsg += str(g & 1)
                        smsg += str(b & 1)
                        smsg += str(a & 1)
                    index += 1
            s1 = smsg
            s1 = smsg.split('0001000100010001')[0]
            
            strg = bitstring_to_bytes(s1)

            ste= ast.literal_eval(key)
            print(type(ste))
            strg=decrypt_message(strg, ste)
            

            # Return the modified image as a response
            return render(request, 'txt-to-image-de.html', {'message': strg})
        except Exception as e:
            return HttpResponseServerError(f'Error: {e}')
    return render(request, 'txt-to-image-de.html')

def img_to_img_encrypt(request):
    if request.method == 'POST':
        # Get the image and message from the POST request
        cov_image = request.FILES.get('cover_image')
        srt_image = request.FILES.get('secret_image')
        try:
            cov_img = Image.open(cov_image)
            srt_img = Image.open(srt_image)
            Steganography().merge(image1=cov_img, image2=srt_img).save("hidden.png")
            with open('hidden.png', 'rb') as f:
                response = HttpResponse(f.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="hidden.png"'
                return response
        except Exception as e:
            return HttpResponseServerError(f'Error: {e}')
    return render(request, 'img_to_img_en.html')

def img_to_img_decrypt(request):
    if request.method == 'POST':
        # Get the image and message from the POST request
        de_image = request.FILES.get('decrypt_image')
        try:
            de_img = Image.open(de_image)
            Steganography().unmerge(image=de_img).save("true.png")
            with open('true.png', 'rb') as f:
                response = HttpResponse(f.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="true.png"'
                return response
        except Exception as e:
            return HttpResponseServerError(f'Error: {e}')
    return render(request, 'img_to_img_de.html')

def txt_to_audio_encrypt(request):
    if request.method == 'POST':
        # retrieve the text to hide in audio
        text = request.POST.get('text')

        # retrieve the audio file to hide text in
        audio_file = request.FILES.get('audio')
        try:
            # read the audio file using wave module
            audio = wave.open(audio_file, 'rb')
            # read audio data
            frame_rate = audio.getframerate()
            num_frames = audio.getnframes()
            data = audio.readframes(num_frames)
            audio.close()
            
            # convert secret message to binary format
            secret_message_bits = text_to_bits(text)
            secret_message_bits += "11111111"
            

            # check if secret message can fit into audio file
            max_message_length = (num_frames * 2) // 8
            if len(secret_message_bits) > max_message_length:
                print("Secret message is too long to embed in audio file.")
                return

            

            # embed secret message into audio data
            message_index = 0
            new_data = bytearray()
            for i in range(len(data)):
                if message_index < len(secret_message_bits):
                    new_byte = (data[i] & 254) | int(
                        secret_message_bits[message_index])
                    message_index += 1
                else:
                    new_byte = data[i]
                new_data.append(new_byte)

            # write modified audio data to new file
            new_audio = wave.open('stego1_audio.wav', mode='wb')
            new_audio.setparams(audio.getparams())
            new_audio.writeframes(new_data)
            new_audio.close()

            with open('stego1_audio.wav', 'rb') as f:
                    response = HttpResponse(f.read(), content_type='stego1_audio.wav')
                    response['Content-Disposition'] = 'attachment; filename="stego1_audio.wav"'
                    return response
        except Exception as e:
            return HttpResponseServerError(f'Error: {e}')
    return render(request, 'audio_en.html')
        
def txt_to_audio_decrypt(request):
    if request.method == 'POST':
        # retrieve the audio file to hide text in
        audio_file = request.FILES.get('audio')
        try:
            # open stego audio file
            audio = wave.open(audio_file, mode='rb')
            # read audio data
            num_frames = audio.getnframes()
            data = audio.readframes(num_frames)
            audio.close()

            # extract secret message from LSBs of audio data
            message_bits = ''
            for byte in data:
                
                message_bits += str(byte & 1)

            # convert binary message to text format
            s1 = message_bits.split('11111111')[0]
            message=''
            for i in range(0, len(s1), 8):
                temp_data = s1[i:i + 8]
                message += chr(int(temp_data, 2))
            # Return the modified image as a response
            return render(request, 'audio_de.html', {'message': message})
        except Exception as e:
            return HttpResponseServerError(f'Error: {e}')
    return render(request, 'audio_de.html')
