#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define SHIFT 1<<14

//convert integer into float
#define I2F(x) ((x)*(SHIFT))

// convert x to integer(rounding toward zero)
#define F2I_R0(x) ((x)/(SHIFT))
//convert x to integer(rounding to nearest)
#define F2I_RN(x) ((x)>=0 ? ((x)+(SHIFT)/2)/(SHIFT) : ((x)-(SHIFT)/2)/(SHIFT))

//add x and y (FLOAT)
#define ADD_F(x,y) ((x)+(y))

// subtract y from x (float)
#define SUB_F(x,y) ((x)-(y))

// float + int
#define ADD_FI(x,n) ((x)+(n)*(SHIFT))

//float - int
#define SUB_FI(x,n) ((x)-(n)*(SHIFT))

//multiply x by y
#define MUL_F(x,y) ((((int64_t)(x))*(y))/(SHIFT))

//multiply x by n(int)
#define MUL_FI(x,n) ((x)*(n))

//divide x by y
#define DIV_F(x,y) ((((int64_t)(x))*(SHIFT))/y)

//divide x by n(int)
#define DIV_FI(x, n) ((x)/(n))

#endif /* threads/fixed-point.h */
