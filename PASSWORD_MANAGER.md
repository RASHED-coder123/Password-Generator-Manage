# مدير كلمات المرور

أداة سطر أوامر محلية مكتوبة ببايثون. لا تحتاج إلى تثبيت أي مكتبات خارجية.

## التشغيل

```powershell
python E:\password_manager.py generate --length 24
```

الأوامر المتاحة:

```text
generate   توليد كلمة مرور
strength   تقييم كلمة مرور (تُقرأ دون إظهارها على الشاشة)
add        إضافة أو تحديث موقع وحساب وكلمة مرور
search     البحث عن موقع وعرض بياناته
list       عرض المواقع والحسابات دون عرض كلمات المرور
```

أمثلة:

```powershell
# توليد كلمة مرور من 16 حرفًا دون رموز
python E:\password_manager.py generate --length 16 --no-symbols

# إضافة سجل؛ إذا لم تُمرر كلمة المرور فسيتم توليدها تلقائيًا
python E:\password_manager.py add example.com user@example.com

# إضافة كلمة مرور محددة
python E:\password_manager.py add github.com user "MySecret!123"

# عرض المواقع المحفوظة ثم البحث
python E:\password_manager.py list
python E:\password_manager.py search github
```

## التخزين والحماية

الخزنة الافتراضية هي:

```text
%USERPROFILE%\.password_manager_vault.json
```

يمكن تغيير مكانها بإضافة `--vault` قبل الأمر، مثل:

```powershell
python E:\password_manager.py --vault E:\vault.json list
```

تُشتق مفاتيح التشفير من كلمة المرور الرئيسية باستخدام PBKDF2-HMAC-SHA256 مع salt عشوائي، وتُحمى البيانات أيضًا بـ HMAC لاكتشاف العبث بالملف. كلمة المرور الرئيسية لا تُحفظ في الملف. احفظ نسخة احتياطية من ملف الخزنة، لأن فقدان كلمة المرور الرئيسية يعني فقدان القدرة على فك البيانات.
