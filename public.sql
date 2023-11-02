PGDMP         )            	    {            postgres    15.4    15.4                0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false                       0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false                       0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false                       1262    5    postgres    DATABASE     |   CREATE DATABASE postgres WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'Russian_Russia.1251';
    DROP DATABASE postgres;
                postgres    false                       0    0    DATABASE postgres    COMMENT     N   COMMENT ON DATABASE postgres IS 'default administrative connection database';
                   postgres    false    3344                        2615    2200    public    SCHEMA        CREATE SCHEMA public;
    DROP SCHEMA public;
                pg_database_owner    false                       0    0    SCHEMA public    COMMENT     6   COMMENT ON SCHEMA public IS 'standard public schema';
                   pg_database_owner    false    5            �            1259    16408    messages    TABLE     �   CREATE TABLE public.messages (
    id integer NOT NULL,
    sender_id integer,
    receiver_id integer,
    message_text text,
    "timestamp" timestamp without time zone DEFAULT CURRENT_TIMESTAMP(0),
    is_read boolean
);
    DROP TABLE public.messages;
       public         heap    postgres    false    5            �            1259    16407    messages_id_seq    SEQUENCE     �   CREATE SEQUENCE public.messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.messages_id_seq;
       public          postgres    false    5    218                       0    0    messages_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.messages_id_seq OWNED BY public.messages.id;
          public          postgres    false    217            �            1259    16399 	   user_data    TABLE     �  CREATE TABLE public.user_data (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    password character varying(100) NOT NULL,
    email character varying(100) NOT NULL,
    fullname character varying(255),
    role character varying(10),
    accepted boolean,
    approved boolean,
    created_on timestamp without time zone DEFAULT CURRENT_TIMESTAMP(0),
    date_birth character varying(15),
    phone_number character varying(255),
    address character varying(255),
    profile_photo character varying(100),
    major character varying(50),
    experience character varying(10),
    skills character varying(255),
    resume character varying(100),
    code character varying(10)
);
    DROP TABLE public.user_data;
       public         heap    postgres    false    5            �            1259    16398    user_data_id_seq    SEQUENCE     �   CREATE SEQUENCE public.user_data_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.user_data_id_seq;
       public          postgres    false    5    216                       0    0    user_data_id_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.user_data_id_seq OWNED BY public.user_data.id;
          public          postgres    false    215            m           2604    16411    messages id    DEFAULT     j   ALTER TABLE ONLY public.messages ALTER COLUMN id SET DEFAULT nextval('public.messages_id_seq'::regclass);
 :   ALTER TABLE public.messages ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    218    217    218            k           2604    16402    user_data id    DEFAULT     l   ALTER TABLE ONLY public.user_data ALTER COLUMN id SET DEFAULT nextval('public.user_data_id_seq'::regclass);
 ;   ALTER TABLE public.user_data ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    215    216    216            
          0    16408    messages 
   TABLE DATA           b   COPY public.messages (id, sender_id, receiver_id, message_text, "timestamp", is_read) FROM stdin;
    public          postgres    false    218                     0    16399 	   user_data 
   TABLE DATA           �   COPY public.user_data (id, username, password, email, fullname, role, accepted, approved, created_on, date_birth, phone_number, address, profile_photo, major, experience, skills, resume, code) FROM stdin;
    public          postgres    false    216   �                  0    0    messages_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.messages_id_seq', 871, true);
          public          postgres    false    217                       0    0    user_data_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.user_data_id_seq', 114, true);
          public          postgres    false    215            p           2606    24625    user_data email_unique 
   CONSTRAINT     R   ALTER TABLE ONLY public.user_data
    ADD CONSTRAINT email_unique UNIQUE (email);
 @   ALTER TABLE ONLY public.user_data DROP CONSTRAINT email_unique;
       public            postgres    false    216            v           2606    16415    messages messages_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.messages DROP CONSTRAINT messages_pkey;
       public            postgres    false    218            r           2606    16406    user_data user_data_pkey 
   CONSTRAINT     V   ALTER TABLE ONLY public.user_data
    ADD CONSTRAINT user_data_pkey PRIMARY KEY (id);
 B   ALTER TABLE ONLY public.user_data DROP CONSTRAINT user_data_pkey;
       public            postgres    false    216            t           2606    24623    user_data username_unique 
   CONSTRAINT     X   ALTER TABLE ONLY public.user_data
    ADD CONSTRAINT username_unique UNIQUE (username);
 C   ALTER TABLE ONLY public.user_data DROP CONSTRAINT username_unique;
       public            postgres    false    216            w           2606    16421 "   messages messages_receiver_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_receiver_id_fkey FOREIGN KEY (receiver_id) REFERENCES public.user_data(id);
 L   ALTER TABLE ONLY public.messages DROP CONSTRAINT messages_receiver_id_fkey;
       public          postgres    false    216    3186    218            x           2606    16416     messages messages_sender_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.user_data(id);
 J   ALTER TABLE ONLY public.messages DROP CONSTRAINT messages_sender_id_fkey;
       public          postgres    false    216    3186    218            
   �   x���=�0��9E{ P�r��]"QD����_�-E�yʖO�����;�$���H��yE^kx
gl��Qu�qG!�rԵ}�wS��-U��L�\i����=�l69�0��/d�Œ��@�vc���B�:4�M���)�&>�F���CJJJʟ��q�Y�(��[�	��elɨ���j���         �  x���io�H�?w~�W�4������4���	GE��/�ݦ}忯1�0���UDI���z��j4���G"��56���ϐ��S$�z�	ځa:���\ls�4�特������-�Ά v��0���_�/�e�G -_b��28$7�	��F�]Ue Ai4���o,&	-��xd�&��ͺ��,�A�~k'AJ���Q�_�?���v��Z��اF�=��2��U��;Zt#����R}���2���$k��#��h���f�e�o�����}��v��8��Y[WU^S�剻�s��s�4cI��!,����]@*ge7��`�K6RS@M��߿���Zt��,Wߨ�Cޚ���=��o�=!�f���*:��l4sF�#�w��|�����W'�^��$���(� )�^����[B6~�9nzF��������t�l��N���"���>3�JV�$+�rȌi~И�M�Xj�V$E�7��W�L�4@�#a�$Q�Re�5�{@���{@ӵ�V$'?�$B(��{�{��w��l��Dظw�H�i��^1Q���]���A%��?b�K�W�ˀ�#�Fܘ����{�)�&� �������RUY��"��$���u�8B��q��a��"�+��b�Xl�h�q͚x�ŵ�.���㳪c;��}������s ���/(��a����&8��]�VGۇ�j;��s�����n��[Poy���2��üGlB e����)�*_����4[u�3�	�a�A�pv�QU�� :a�7�/�"T��������lb��<�k$r�5a���͜]y��G\���FH[c�y���3��(�T²�����4Xt�E�ļ��M��>��@��?s��R��:cn�&�CY��?,~������O�DIVjr�P��t����)j�1Ѿ���G�rl�?q����؋�r�o�V]V��
U��,�'���WWW�>     