#ifndef _VOID_TO_FUNCTION_CAST_HPP
#define _VOID_TO_FUNCTION_CAST_HPP

template <class T>
class BasicConstructor {
  public:
    typedef T * (*fp)(void);
    BasicConstructor (fp func) : mFunction(func) {}
    T *operator() () {
      return (mFunction)();
    }
  private:
    fp mFunction;
};

template <class T,class U>
class SinglePointerConstructor {
  public:
    typedef T * (*fp)(U *);
    SinglePointerConstructor (fp func) : mFunction(func) {}
    T *operator() (U *val) {
      return (mFunction)(val);
    }
  private:
    fp mFunction;
};


template <class T>
class VoidToFunction {
 public:
  static T *cast(void *p) {
#ifdef VOID_FP_CAST_WORKAROUND
#ifdef POINTERS_64BIT
      return new T(reinterpret_cast<typename T::fp>(reinterpret_cast<long long>(p)));
#else
      return new T(reinterpret_cast<typename T::fp>(reinterpret_cast<int>(p)));
#endif 
#else
      return new T(reinterpret_cast<typename T::fp>(p));
#endif
  };
};

#endif 

