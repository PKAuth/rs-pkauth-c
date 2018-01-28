
use std::any::{Any, TypeId};

pub struct StablePtr<T> {
    ptr : *mut T,
    type_id : TypeId
}

pub fn new_stable_ptr<T : Any>( o : T) -> StablePtr<T> {
    StablePtr {
        ptr : Box::into_raw( Box::new( o)),
        type_id : TypeId::of::<T>()
    }
}

pub fn free_stable_ptr<T : Any>( ptr : StablePtr<T>) {
    //  Make sure we actually have a T.
    assert!( ptr.type_id == TypeId::of::<T>(), "Could not free StablePtr of expected type {:?}. Actual type is {:?}.", TypeId::of::<T>(), ptr.type_id);

    // JP: Check for null?

    // Free ptr.
    unsafe {
        Box::from_raw( ptr.ptr);
    }
}

pub fn deref_stable_ptr<'a, T>( ptr : StablePtr<T>) -> &'a T {
    //  Make sure we actually have a T.
    assert!( ptr.type_id == TypeId::of::<T>(), "Could not dereference StablePtr of expected type {:?}. Actual type is {:?}.", TypeId::of::<T>(), ptr.type_id);
    
    unsafe {
        ptr.ptr.as_ref().unwrap()
    }
}
