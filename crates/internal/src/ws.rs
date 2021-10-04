use nom::bytes::complete::take_while;
use nom::error::ParseError;
use nom::{IResult, InputIter, InputLength, InputTakeAtPosition};

pub trait WsTuple<I, O, E> {
    fn parse(&mut self, i: I) -> IResult<I, O, E>;
}

/// Take a list of parsers and insert a take_while(whitespace) before each
#[inline]
pub fn ws<I, O, E, L>(mut l: L) -> impl FnMut(I) -> IResult<I, O, E>
where
    I: InputLength + InputIter + InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: Into<char>,
    E: ParseError<I>,
    L: WsTuple<I, O, E>,
{
    move |i: I| l.parse(i)
}

fn whitespace(c: impl Into<char>) -> bool {
    c.into().is_ascii_whitespace()
}

macro_rules! ws_impl {
    (
        $gen:ident $gen_fn:ident;
        $($r_gen:ident $r_gen_fn:ident;)*
    ) => {
        ws_impl!(
            @impl_
            $gen $gen_fn;
            $($r_gen $r_gen_fn;)*
        );

        ws_impl!(
            $($r_gen $r_gen_fn;)*
        );
    };
    (@impl_ $($gen:ident $gen_fn:ident;)+) => {
        impl<
            $($gen,)*
            Input: InputLength + InputIter + InputTakeAtPosition,
            Error: ParseError<Input>,
            $(
                $gen_fn: FnMut(Input) -> IResult<Input, $gen, Error>,
            )*
            >
            WsTuple<Input, ($($gen,)*), Error> for ($($gen_fn,)*)
            where
                <Input as InputTakeAtPosition>::Item: Into<char>,
            {
                #[allow(non_snake_case)]
                fn parse(&mut self, input: Input) -> IResult<Input, ( $($gen,)* ), Error> {
                    let ($($gen_fn,)*) = self;

                    $(
                    let (input, _) = take_while(whitespace)(input)?;
                    let (input, $gen) = ($gen_fn)(input)?;
                    )*

                    Ok((input, ($($gen,)*)))
                }
            }
    };
    () => {}
}

ws_impl! {
    A FnA;
    B FnB;
    C FnC;
    D FnD;
    E FnE;
    F FnF;
    G FnG;
    H FnH;
    I FnI;
    J FnJ;
    K FnK;
    L FnL;
    M FnM;
    N FnN;
    O FnO;
}
