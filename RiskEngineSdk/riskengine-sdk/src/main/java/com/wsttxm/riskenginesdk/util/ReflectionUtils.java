package com.wsttxm.riskenginesdk.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class ReflectionUtils {

    public static Object getField(Object obj, String fieldName) {
        try {
            Class<?> clazz = obj.getClass();
            while (clazz != null) {
                try {
                    Field field = clazz.getDeclaredField(fieldName);
                    field.setAccessible(true);
                    return field.get(obj);
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
        } catch (Exception e) {
            CLog.e("ReflectionUtils getField failed: " + fieldName, e);
        }
        return null;
    }

    public static Object getStaticField(Class<?> clazz, String fieldName) {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(null);
        } catch (Exception e) {
            CLog.e("ReflectionUtils getStaticField failed: " + fieldName, e);
        }
        return null;
    }

    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramTypes, Object... args) {
        try {
            Method method = obj.getClass().getDeclaredMethod(methodName, paramTypes);
            method.setAccessible(true);
            return method.invoke(obj, args);
        } catch (Exception e) {
            CLog.e("ReflectionUtils invokeMethod failed: " + methodName, e);
        }
        return null;
    }

    public static Object invokeStaticMethod(Class<?> clazz, String methodName, Class<?>[] paramTypes, Object... args) {
        try {
            Method method = clazz.getDeclaredMethod(methodName, paramTypes);
            method.setAccessible(true);
            return method.invoke(null, args);
        } catch (Exception e) {
            CLog.e("ReflectionUtils invokeStaticMethod failed: " + methodName, e);
        }
        return null;
    }
}
